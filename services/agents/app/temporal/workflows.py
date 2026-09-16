"""Temporal workflow — durable overlay for the LangGraph investigation pipeline.

``InvestigationWorkflow`` runs the same 5-phase sequence as the fixed
LangGraph pipeline (auto-triage → evidence/discovery → compression → RCA →
response), but each phase executes as a Temporal *activity*
(:mod:`app.temporal.activities`) so the whole run survives worker restarts,
network blips, and long human-in-the-loop waits. Every activity delegates
to the same node function :mod:`app.graph.workflow` uses for the in-process
graph, so investigation logic is never duplicated — only the orchestration.

Design notes specific to Temporal's deterministic-replay requirement:

* The workflow only ever manipulates plain ``dict`` state — it never
  constructs :class:`app.models.state.InvestigationState` directly, because
  that model's ``run_id``/``started_at`` fields use non-deterministic
  ``default_factory`` callables (``uuid4``, ``datetime.utcnow``). Building
  the initial dict by hand and letting *activities* (which run outside the
  workflow sandbox) validate/rebuild the model keeps workflow code
  deterministic.
* Activities are referenced by their registered string name rather than by
  importing the activity functions, so this module never imports
  ``app.graph.workflow`` (and therefore never imports LangGraph) inside the
  sandboxed workflow environment.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

_ACTIVITY_TIMEOUT = timedelta(minutes=3)
# parallel_analysis fans out swarm-LLM + RCA-narrative-LLM + phase hunts in
# one activity; single-model backends (LM Studio) serialize the LLM calls,
# so the combined leg needs more headroom than a single-track phase.
_PARALLEL_ANALYSIS_TIMEOUT = timedelta(minutes=8)
_ACTIVITY_RETRY_POLICY = RetryPolicy(
    maximum_attempts=5,
    # A pydantic ValidationError (e.g. a non-UUID incident_id/tenant_id
    # slipping past the adapter's validation) is a permanent failure — no
    # amount of retrying will fix bad input, so don't retry it into an
    # unbounded loop. Everything else (transient LLM/DB/network errors)
    # still gets the bounded 5-attempt retry above.
    non_retryable_error_types=["ValidationError"],
)
_DEFAULT_CONFIDENCE_THRESHOLD = 0.6
_DEFAULT_MAX_ITERATIONS = 10
_APPROVAL_TIMEOUT = timedelta(hours=1)


@workflow.defn(name="InvestigationWorkflow")
class InvestigationWorkflow:
    """Durable ReAct-supervised investigation.

    auto_triage → triage → [supervisor → chosen action]* → finalize_response.
    The supervisor evaluates the investigation blackboard each iteration and
    selects the next activity dynamically (gather_evidence / compress_events /
    run_swarm / perform_rca / parallel_analysis / finalize_response), matching
    the LangGraph supervised graph — not a static phase list.
    """

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}
        self._phase: str = "pending"
        # Every phase entered, in order — the adapter replays this into step
        # events. Sampling the current phase alone misses fast phases that
        # complete between the adapter's 2-second polls.
        self._phase_history: list[str] = []
        self._awaiting_approval: bool = False
        self._approved: bool | None = None

    # ------------------------------------------------------------------
    # Signals / queries — HITL approval gate + progress visibility.
    # ------------------------------------------------------------------

    @workflow.signal
    async def approve(self, approved: bool) -> None:
        """Resolve the HITL approval gate opened by :meth:`_await_approval`."""
        self._approved = approved

    @workflow.query(name="get_progress")
    def get_progress(self) -> dict[str, Any]:
        """Return the current phase + a snapshot of the accumulated state.

        Polled by :class:`app.temporal.adapter.TemporalOrchestratorAdapter`
        to synthesise the ``step`` events the in-process streaming
        orchestrators emit natively.
        """
        return {
            "phase": self._phase,
            "phase_history": list(self._phase_history),
            "awaiting_approval": self._awaiting_approval,
            "verdict": self._state.get("verdict"),
            "confidence": self._state.get("confidence"),
            "findings_count": len(self._state.get("findings", []) or []),
            "supervisor_history": self._state.get("supervisor_history", []),
            "supervisor_action": self._state.get("_supervisor_action"),
            "supervisor_goal": self._state.get("_supervisor_goal"),
        }

    # ------------------------------------------------------------------
    # Main entrypoint.
    # ------------------------------------------------------------------

    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        max_iterations = int(request.get("max_iterations", _DEFAULT_MAX_ITERATIONS))

        state: dict[str, Any] = {
            "run_id": workflow.info().workflow_id,
            "incident_id": request["incident_id"],
            "tenant_id": request["tenant_id"],
            "tenant_ref": request.get("tenant_ref", request["tenant_id"]),
            "alert_summary": request.get("alert_summary", ""),
            "raw_alert": request.get("raw_alert", {}),
            "status": "running",
            "findings": [],
            "confidence": 0.0,
        }

        # Phase 0 — auto-triage. Mirrors the LangGraph pipeline's early exit:
        # a high-confidence auto-closed verdict skips the rest of the run —
        # but ONLY for automatic alert-stream triage. When an analyst
        # explicitly requested this investigation (the case "Investigate
        # with agent" button), the whole point is the full pipeline: keep
        # the auto-triage verdict as a finding and continue so evidence,
        # kill-chain hunts, swarm/RCA and the forensic report all run.
        analyst_requested = bool(request.get("analyst_requested", True))
        state = await self._run_phase("auto_triage", state)
        if state.get("status") == "completed":
            if not analyst_requested:
                self._phase = "completed"
                return state
            state["status"] = "running"
            state.setdefault("findings", []).append(
                "Auto-triage recommended closure, but analyst requested a full "
                "investigation — continuing through all phases"
            )

        # Phase 1 — initial deterministic triage.
        state = await self._run_phase("triage", state)

        # Autonomous ReAct supervisor loop (matches the LangGraph supervised
        # graph): the supervisor evaluates the investigation blackboard,
        # detects evidence gaps, and selects the next activity dynamically.
        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            state = await self._run_phase("supervisor", state)
            action = state.get("_supervisor_action", "finalize_response")

            if action == "finalize_response":
                break
            if action in ("gather_evidence", "run_specialist"):
                state = await self._run_phase("gather_evidence", state)
            elif action == "compress_events":
                state = await self._run_phase("compress_events", state)
            elif action == "run_swarm":
                state = await self._run_phase("run_swarm", state)
            elif action == "perform_rca":
                state = await self._run_phase("perform_rca", state)
            elif action == "parallel_analysis":
                state = await self._run_phase("parallel_analysis", state)
            else:
                break

        # HITL approval gate — only when the investigation proposed actions
        # that require sign-off (mirrors ProposedAction.requires_approval).
        proposed_actions = state.get("proposed_actions") or []
        if any(isinstance(a, dict) and a.get("requires_approval") for a in proposed_actions):
            await self._await_approval()
            if self._approved is False:
                state.setdefault("findings", []).append("Proposed actions rejected by reviewer.")
                state["proposed_actions"] = []

        state = await self._run_phase("finalize_response", state)
        self._phase = "completed"
        return state

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _run_phase(self, name: str, state: dict[str, Any]) -> dict[str, Any]:
        self._phase = name
        self._phase_history.append(name)
        self._state = state
        timeout = (
            _PARALLEL_ANALYSIS_TIMEOUT if name == "parallel_analysis" else _ACTIVITY_TIMEOUT
        )
        result = await workflow.execute_activity(
            name,
            state,
            start_to_close_timeout=timeout,
            retry_policy=_ACTIVITY_RETRY_POLICY,
        )
        self._state = result
        return result

    async def _await_approval(self) -> None:
        self._awaiting_approval = True
        self._phase = "waiting_approval"
        try:
            await workflow.wait_condition(lambda: self._approved is not None, timeout=_APPROVAL_TIMEOUT)
        except TimeoutError:
            # No reviewer response within the window — default to rejecting
            # the proposed actions rather than silently auto-approving them.
            self._approved = False
        finally:
            self._awaiting_approval = False
