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
_DEFAULT_MAX_REINVESTIGATIONS = 2
_APPROVAL_TIMEOUT = timedelta(hours=1)

# Phases that repeat in the adaptive re-investigation loop when confidence
# stays below threshold — mirrors the supervised graph's ReAct posture, but
# as a bounded, durable, queryable loop rather than an open-ended one.
_INVESTIGATION_PHASES = (
    "triage",
    "gather_evidence",
    "compress_events",
    "run_swarm",
    "perform_rca",
)


@workflow.defn(name="InvestigationWorkflow")
class InvestigationWorkflow:
    """Durable 5-phase investigation: Triage → Evidence → Compression → RCA → Response."""

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}
        self._phase: str = "pending"
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
            "awaiting_approval": self._awaiting_approval,
            "verdict": self._state.get("verdict"),
            "confidence": self._state.get("confidence"),
            "findings_count": len(self._state.get("findings", []) or []),
        }

    # ------------------------------------------------------------------
    # Main entrypoint.
    # ------------------------------------------------------------------

    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        confidence_threshold = float(request.get("confidence_threshold", _DEFAULT_CONFIDENCE_THRESHOLD))
        max_reinvestigations = int(request.get("max_reinvestigations", _DEFAULT_MAX_REINVESTIGATIONS))

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
        # a high-confidence auto-closed verdict skips the rest of the run.
        state = await self._run_phase("auto_triage", state)
        if state.get("status") == "completed":
            self._phase = "completed"
            return state

        attempt = 0
        while True:
            for phase in _INVESTIGATION_PHASES:
                state = await self._run_phase(phase, state)

            confidence = float(state.get("confidence", 0.0) or 0.0)
            attempt += 1
            if confidence >= confidence_threshold or attempt > max_reinvestigations:
                break
            state.setdefault("findings", []).append(
                f"Re-investigating (attempt {attempt}): confidence {confidence:.2f} "
                f"below threshold {confidence_threshold:.2f}"
            )

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
        self._state = state
        result = await workflow.execute_activity(
            name,
            state,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
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
