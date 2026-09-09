"""ReAct Supervisor — LLM-driven observe → reason → act loop.

The supervisor observes the investigation blackboard (``InvestigationState``),
reasons about forensic gaps, and dynamically selects the next action — rather
than following a static pipeline.

Architecture
============

The supervisor is a **node** in a LangGraph ``StateGraph`` that acts as a
central routing hub.  After each action completes, the graph re-enters the
supervisor node, which re-observes the updated state and decides the next
step.  This continues until the supervisor selects ``finalize_response`` or
the budget is exhausted.

::

    START → auto_triage → supervisor ←──────────────────────────┐
                             │                                   │
                             ├─► gather_evidence ───────────────►│
                             ├─► run_specialist ────────────────►│
                             ├─► compress_events ───────────────►│
                             ├─► run_swarm ─────────────────────►│
                             ├─► perform_rca ───────────────────►│
                             └─► finalize_response ──────────► END

Feature flag
============

``AISOC_AGENT_SUPERVISED_MODE`` (env, default ``0``).  Set to ``1`` to enable
the supervisor loop; the default remains the fixed pipeline.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()

_SUPERVISED_FLAG = "AISOC_AGENT_SUPERVISED_MODE"

# Valid actions the supervisor can select.
VALID_ACTIONS = frozenset({
    "gather_evidence",
    "run_specialist",
    "compress_events",
    "run_swarm",
    "perform_rca",
    "finalize_response",
})


def is_supervised_mode_enabled() -> bool:
    """Return True if the supervisor loop is enabled."""
    raw = os.getenv(_SUPERVISED_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


@dataclass
class SupervisorDecision:
    """A single decision from the supervisor."""

    assessment: str          # High-level assessment of the investigation state
    thought: str             # Chain-of-thought reasoning
    action: str              # The action to take next
    target_entities: list[str] = field(default_factory=list)
    specific_goal: str = ""
    target_skills: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment,
            "thought": self.thought,
            "action": self.action,
            "target_entities": self.target_entities,
            "specific_goal": self.specific_goal,
        }


class ReActSupervisor:
    """LLM-driven autonomous supervisor for the investigation loop.

    Usage::

        supervisor = ReActSupervisor()
        decision = await supervisor.decide(state)
    """

    def __init__(
        self,
        *,
        litellm_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self._litellm_url = litellm_url or os.getenv("LITELLM_URL", "http://litellm:4000")
        self._model = model or os.getenv("AISOC_SUPERVISOR_MODEL", "gpt-4o-mini")

    async def decide(self, state: InvestigationState) -> SupervisorDecision:
        """Observe the investigation state and decide the next action.

        Falls back to a deterministic heuristic if the LLM is unavailable.
        """
        start = time.monotonic()

        # Hard global stop: the runner's total tool-call budget
        # (``InvestigationBudget.max_tool_calls``, threaded through as
        # ``state.max_iterations``) has been exhausted. Force finalize
        # regardless of what the LLM/heuristic would otherwise pick, and
        # skip ``_validate`` (whose "can't finalize without findings" rule
        # would otherwise fight this and loop forever).
        if state.iteration_count >= state.max_iterations:
            logger.warning(
                "supervisor.tool_call_budget_exhausted",
                iteration_count=state.iteration_count,
                max_iterations=state.max_iterations,
            )
            return SupervisorDecision(
                assessment=(
                    f"Tool-call budget ({state.max_iterations}) exhausted after "
                    f"{state.iteration_count} iterations. Finalizing with available evidence."
                ),
                thought="Global iteration/tool-call cap reached; forcing finalize_response.",
                action="finalize_response",
                specific_goal="Generate response plan with available evidence before budget cutoff",
            )

        # Build the observation prompt.
        prompt = self._build_prompt(state)

        try:
            decision = await self._llm_decide(prompt)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "supervisor.llm_failed_using_heuristic",
                error=str(exc).replace("\r", "").replace("\n", " ")[:200],
            )
            decision = self._heuristic_fallback(state)

        # Validate and sanitize the decision.
        decision = self._validate(decision, state)

        latency_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "supervisor.decision",
            action=decision.action,
            goal=decision.specific_goal[:100],
            latency_ms=latency_ms,
            iteration=state.iteration_count,
        )

        return decision

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(self, state: InvestigationState) -> str:
        entities_summary = ""
        if state.entities:
            parts = []
            for e in state.entities[:20]:
                if isinstance(e, dict):
                    parts.append(f"{e.get('type', '?')}:{e.get('id', '?')}")
                else:
                    parts.append(str(e))
            entities_summary = ", ".join(parts)

        findings_summary = "\n".join(f"- {f}" for f in (state.findings or [])[-10:])
        action_history = ", ".join(
            f"{a}={c}" for a, c in (state.action_counts or {}).items()
        )

        rca_conf = (state.rca_findings or {}).get("confidence", 0.0)
        compressed = "yes" if state.compressed_events else "no"

        return (
            "You are a senior SOC investigation supervisor. Observe the current "
            "investigation state and decide the SINGLE best next action.\n\n"
            "AVAILABLE ACTIONS:\n"
            "- gather_evidence: Collect forensic evidence from entities\n"
            "- run_specialist: Run a specialist agent (phishing/identity/cloud/insider)\n"
            "- compress_events: Run 7-stage noise compression on collected events\n"
            "- run_swarm: Run competing hypothesis swarm for complex cases\n"
            "- perform_rca: Run PageRank root cause analysis on the causal graph\n"
            "- finalize_response: Generate final response plan and close investigation\n\n"
            "RULES:\n"
            "- You MUST select finalize_response when RCA confidence >= 0.75\n"
            "- You MUST select compress_events before perform_rca\n"
            "- You MUST select finalize_response if all action budgets are exhausted\n"
            "- Each action can run at most 3 times\n\n"
            "CURRENT STATE:\n"
            f"Alert: {state.alert_summary}\n"
            f"Entities: {entities_summary or 'none identified'}\n"
            f"Findings: {findings_summary or 'none yet'}\n"
            f"Compressed: {compressed}\n"
            f"RCA confidence: {rca_conf}\n"
            f"Action history: {action_history or 'none'}\n"
            f"Iteration: {state.iteration_count}/{state.max_iterations}\n\n"
            "Respond with a JSON object: {\"assessment\": \"...\", \"thought\": \"...\", "
            "\"action\": \"...\", \"target_entities\": [...], \"specific_goal\": \"...\"}"
        )

    # ------------------------------------------------------------------
    # LLM decision
    # ------------------------------------------------------------------

    async def _llm_decide(self, prompt: str) -> SupervisorDecision:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._litellm_url}/v1/chat/completions",
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 500,
                    "response_format": {"type": "json_object"},
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)

            action = str(parsed.get("action", "finalize_response"))
            if action not in VALID_ACTIONS:
                action = "finalize_response"

            return SupervisorDecision(
                assessment=str(parsed.get("assessment", "")),
                thought=str(parsed.get("thought", "")),
                action=action,
                target_entities=list(parsed.get("target_entities", [])),
                specific_goal=str(parsed.get("specific_goal", "")),
            )

    # ------------------------------------------------------------------
    # Heuristic fallback (deterministic, no LLM)
    # ------------------------------------------------------------------

    def _heuristic_fallback(self, state: InvestigationState) -> SupervisorDecision:
        """Deterministic decision tree when the LLM is unavailable."""
        counts = state.action_counts or {}
        max_iter = state.max_action_iterations

        # Phase 1: Gather evidence if not done yet.
        if counts.get("gather_evidence", 0) < max_iter and not state.entities:
            return SupervisorDecision(
                assessment="Initial triage completed. Need forensic evidence.",
                thought="No entities collected yet. Running evidence collection.",
                action="gather_evidence",
                specific_goal="Gather baseline evidence for triage entities",
            )

        # Phase 2: Compress events if not done yet.
        if not state.compressed_events and counts.get("compress_events", 0) < max_iter:
            return SupervisorDecision(
                assessment="Evidence collected. Raw events need compression.",
                thought="Evidence collected but timeline not compressed. Running compression.",
                action="compress_events",
                specific_goal="Compress collected evidence into high-signal timeline",
            )

        # Phase 3: Run RCA if confidence is low.
        rca_conf = (state.rca_findings or {}).get("confidence", 0.0)
        if rca_conf < 0.70 and counts.get("perform_rca", 0) < max_iter:
            return SupervisorDecision(
                assessment="Compressed timeline ready. Running root cause analysis.",
                thought="Timeline ready. Performing RCA and attack chain reconstruction.",
                action="perform_rca",
                specific_goal="Reconstruct attack chain and score causal confidence",
            )

        # Phase 4: Finalize.
        rca_conf = (state.rca_findings or {}).get("confidence", 0.0)
        root_cause = (state.rca_findings or {}).get("root_cause_entity", "")

        if rca_conf >= 0.75 and root_cause:
            assessment = (
                f"Investigation goal achieved: root cause resolved with "
                f"{int(rca_conf * 100)}% confidence. Proceeding to response."
            )
        else:
            exhausted = [a for a, c in counts.items() if c >= max_iter]
            exhausted_str = f" ({', '.join(exhausted)} at cap)" if exhausted else ""
            assessment = (
                f"Phase quota reached: RCA confidence at {int(rca_conf * 100)}%"
                f"{exhausted_str}. Finalizing with available evidence."
            )

        return SupervisorDecision(
            assessment=assessment,
            thought="Finalizing response plan.",
            action="finalize_response",
            specific_goal="Generate prioritized containment and remediation plan",
        )

    # ------------------------------------------------------------------
    # Decision validation
    # ------------------------------------------------------------------

    def _validate(
        self, decision: SupervisorDecision, state: InvestigationState
    ) -> SupervisorDecision:
        """Ensure the chosen action is executable given the current state."""
        counts = state.action_counts or {}
        max_iter = state.max_action_iterations

        # Drop any target_entities the LLM invented/hallucinated that aren't
        # part of the observed investigation blackboard, so a prompt-injected
        # or hallucinated entity reference can never be acted on downstream.
        decision = self._sanitize_entities(decision, state)

        # Advisory-only: log when the stated goal has drifted from the
        # original investigative context. Does not block the action, since
        # some goal evolution across phases (gather -> compress -> RCA) is
        # expected and legitimate.
        self._detect_goal_drift(decision, state)

        # Enforce per-action limits.
        if counts.get(decision.action, 0) >= max_iter:
            logger.warning(
                "supervisor.action_at_cap_forcing_fallback",
                action=decision.action,
                count=counts.get(decision.action, 0),
            )
            return self._heuristic_fallback(state)

        # Can't run RCA without compressed events.
        if decision.action == "perform_rca" and not state.compressed_events:
            decision.action = "compress_events"
            decision.specific_goal = "Must compress events before RCA"

        # Can't finalize without at least one investigation step.
        if decision.action == "finalize_response" and not state.findings:
            decision.action = "gather_evidence"
            decision.specific_goal = "Need at least one investigation step before finalizing"

        return decision

    @staticmethod
    def _sanitize_entities(
        decision: SupervisorDecision, state: InvestigationState
    ) -> SupervisorDecision:
        """Filter ``target_entities`` down to entities actually observed on
        the investigation blackboard (``state.entities``) or referenced by
        the original alert. The LLM's ``target_entities`` field is untrusted
        output parsed straight from JSON — without this filter, a
        hallucinated or prompt-injected entity reference would flow
        unfiltered into whatever downstream tool/action consumes it.
        """
        if not decision.target_entities:
            return decision

        known: set[str] = set()
        for entity in state.entities or []:
            if isinstance(entity, dict) and entity.get("id"):
                known.add(str(entity["id"]))
        for key in ("hostname", "username", "src_ip", "dst_ip", "entity_id", "entity"):
            value = (state.raw_alert or {}).get(key)
            if value:
                known.add(str(value))

        sanitized = [e for e in decision.target_entities if str(e) in known]
        dropped = [e for e in decision.target_entities if str(e) not in known]
        if dropped:
            logger.warning("supervisor.dropped_unknown_target_entities", dropped=dropped[:10])
        decision.target_entities = sanitized
        return decision

    @staticmethod
    def _detect_goal_drift(decision: SupervisorDecision, state: InvestigationState) -> None:
        """Log when the supervisor's stated goal shares no vocabulary with
        the original investigative context (the first recorded goal, or the
        alert summary if this is the first decision). Heuristic and
        advisory only — goal evolution across phases is expected.
        """
        if not state.supervisor_history:
            return  # this decision establishes the goal baseline

        baseline = str(state.supervisor_history[0].get("specific_goal", "")) or state.alert_summary
        current = decision.specific_goal or ""
        baseline_words = {w for w in re.findall(r"[a-z0-9]{4,}", baseline.lower())}
        current_words = {w for w in re.findall(r"[a-z0-9]{4,}", current.lower())}
        if not baseline_words or not current_words:
            return

        overlap = len(baseline_words & current_words) / len(baseline_words)
        if overlap == 0:
            logger.warning(
                "supervisor.goal_drift_detected",
                baseline_goal=baseline[:150],
                current_goal=current[:150],
                iteration=state.iteration_count,
            )
