"""
LangGraph workflow: wires Auto-Triage → Triage → Enrichment → Investigation
→ Attack-Path agents.

Auto-triage runs first.  If the LLM classifies the alert as FP/benign with
confidence above the auto-close threshold the graph terminates early.
Otherwise the alert flows through the full manual pipeline, ending with the
graph-aware Attack-Path agent that walks Neo4j to compute blast radius.
"""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from app.agents.attack_path_agent import run_attack_path
from app.agents.auto_triage_agent import AutoTriageError, run_auto_triage
from app.agents.enrichment_agent import run_enrichment
from app.agents.investigation_agent import run_investigation
from app.agents.triage_agent import run_triage
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


def _state_dict(state: InvestigationState) -> dict:
    return state.to_dict()


def _from_dict(d: dict) -> InvestigationState:
    return InvestigationState.model_validate(d)


# ---- Node wrappers (LangGraph uses dict state, we wrap our Pydantic model) ----


async def auto_triage_node(state: dict) -> dict:
    s = _from_dict(state)
    try:
        s = await run_auto_triage(s)
    except AutoTriageError as exc:
        # LLM/parse failure (issue #571): never terminate on a null verdict —
        # escalate through the full pipeline (deterministic triage runs next).
        logger.warning("graph.auto_triage_failed_escalating", error=str(exc), incident_id=str(s.incident_id))
        s.add_finding(f"Auto-triage LLM unavailable ({exc}) — escalating to full pipeline")
        if s.status is AgentStatus.COMPLETED:
            s.status = AgentStatus.RUNNING
    return s.to_dict()


async def triage_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_triage(s)
    return s.to_dict()


async def enrichment_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_enrichment(s)
    return s.to_dict()


async def investigation_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_investigation(s)
    return s.to_dict()


async def attack_path_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_attack_path(s)
    return s.to_dict()


def _should_continue(state: dict) -> str:
    """Conditional edge: stop if max iterations reached or status is terminal."""
    s = _from_dict(state)
    if s.iteration_count >= s.max_iterations:
        return "end"
    if s.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED):
        return "end"
    return "continue"


def _after_auto_triage(state: dict) -> str:
    """Route after auto-triage: auto-closed alerts go to END, others continue."""
    s = _from_dict(state)
    if s.status == AgentStatus.COMPLETED:
        return "end"
    return "continue"


def build_investigation_graph() -> StateGraph:
    """Build and compile the investigation workflow graph.

    Flow:
        auto_triage ─┬─ (high-confidence FP/benign) ──► END
                      └─ (else) ──► triage ──► enrichment ──► investigation
                                          ──► attack_path ──► END
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)

    graph.set_entry_point("auto_triage")

    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "triage"},
    )
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)

    return graph.compile()


def build_escalation_graph() -> StateGraph:
    """The post-triage escalation pipeline (issue #569).

    Shares the SAME node implementations as the full graph but skips the
    auto-triage entry node — used by the Kafka auto-triage worker, which has
    already produced a governed verdict, to route escalated alerts (TP /
    low-confidence / needs_review) through enrichment → investigation →
    attack-path without re-triaging.

    Flow: triage ──► enrichment ──► investigation ──► attack_path ──► END
    """
    graph = StateGraph(dict)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)
    graph.set_entry_point("triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)
    return graph.compile()


# Module-level compiled graphs (singletons)
investigation_graph = build_investigation_graph()
escalation_graph = build_escalation_graph()


# ---------------------------------------------------------------------------
# Supervised investigation graph (v8.1 — ReAct supervisor loop)
# ---------------------------------------------------------------------------
#
# Feature flag: AISOC_AGENT_SUPERVISED_MODE (default off).
#
# Topology:
#     START → auto_triage → supervisor ←──────────────────────┐
#                              │                               │
#                              ├─► gather_evidence ───────────►│
#                              ├─► run_specialist ────────────►│
#                              ├─► compress_events ───────────►│
#                              ├─► run_swarm ─────────────────►│
#                              ├─► perform_rca ───────────────►│
#                              └─► finalize_response ───────► END


async def supervisor_node(state: dict) -> dict:
    """Supervisor node: observe state → decide next action."""
    from app.orchestrator.supervisor import ReActSupervisor  # noqa: PLC0415

    s = _from_dict(state)
    supervisor = ReActSupervisor()
    decision = await supervisor.decide(s)

    # Record the decision in the audit trail.
    s.supervisor_history.append(decision.to_dict())

    # Update action counter.
    counts = dict(s.action_counts or {})
    counts[decision.action] = counts.get(decision.action, 0) + 1
    s.action_counts = counts
    s.iteration_count += 1

    # Store the chosen action in a routing key for the conditional edge.
    d = s.to_dict()
    d["_supervisor_action"] = decision.action
    d["_supervisor_goal"] = decision.specific_goal
    d["_supervisor_entities"] = decision.target_entities
    return d


async def gather_evidence_node(state: dict) -> dict:
    """Gather forensic evidence from entities."""
    s = _from_dict(state)
    s = await run_enrichment(s)
    s.add_finding("Evidence gathering completed via enrichment agent")
    return s.to_dict()


async def compress_events_node(state: dict) -> dict:
    """Run the 7-stage noise compression pipeline."""
    s = _from_dict(state)
    try:
        from app.compression.pipeline import CompressionPipeline  # noqa: PLC0415

        pipeline = CompressionPipeline()
        # Compress raw alert data + findings into a compressed package.
        raw_events = []
        if s.raw_alert:
            raw_events.append(s.raw_alert)
        for entity in s.entities:
            if isinstance(entity, dict):
                raw_events.append(entity)

        if raw_events:
            package = pipeline.compress(raw_events, investigation_id=str(s.incident_id))
            s.compressed_events = [e.to_dict() for e in package.events]
            s.add_finding(
                f"Compression: {package.original_event_count} → "
                f"{package.compressed_event_count} events "
                f"({package.compression_ratio:.1f}x reduction)"
            )
        else:
            s.add_finding("Compression: no raw events to compress")
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"Compression failed: {exc}")
        logger.warning("supervised.compress_failed", error=str(exc))
    return s.to_dict()


async def run_swarm_node(state: dict) -> dict:
    """Run the competing hypothesis swarm."""
    s = _from_dict(state)
    try:
        from app.swarm import hold_debate, run_swarm_llm  # noqa: PLC0415

        signal = {
            "alert_summary": s.alert_summary,
            "techniques": s.mitre_mappings,
            "entities": s.entities,
            **(s.raw_alert or {}),
        }
        results = await run_swarm_llm(signal)
        outcome = hold_debate(results)
        if outcome.winner:
            s.add_finding(
                f"Swarm winner: {outcome.winner.label} "
                f"(confidence: {outcome.winner.confidence:.2f})"
            )
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"Swarm failed: {exc}")
        logger.warning("supervised.swarm_failed", error=str(exc))
    return s.to_dict()


async def perform_rca_node(state: dict) -> dict:
    """Run PageRank root cause analysis."""
    s = _from_dict(state)
    try:
        from app.compression.models import CorrelatedEvent  # noqa: PLC0415
        from app.compression.stages import normalise_event  # noqa: PLC0415
        from app.rca.causal_graph import CausalGraphBuilder  # noqa: PLC0415
        from app.rca.pagerank_scorer import PageRankRCA  # noqa: PLC0415

        # Build events from compressed_events or entities.
        events = [normalise_event(e) for e in (s.compressed_events or s.entities or [])]
        target = events[0].entity_id if events else "unknown"

        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, target, events)
        s.rca_findings = result.to_dict()
        s.add_finding(
            f"RCA: root cause is '{result.root_cause_entity}' "
            f"(confidence: {result.confidence:.2f}, "
            f"blast radius: {result.estimated_blast_radius})"
        )
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"RCA failed: {exc}")
        logger.warning("supervised.rca_failed", error=str(exc))
    return s.to_dict()


async def finalize_response_node(state: dict) -> dict:
    """Generate final response plan and close the investigation."""
    s = _from_dict(state)
    s.status = AgentStatus.COMPLETED
    s.add_finding("Investigation finalized by supervisor")
    return s.to_dict()


def _supervisor_route(state: dict) -> str:
    """Route based on the supervisor's chosen action."""
    action = state.get("_supervisor_action", "finalize_response")
    if action == "finalize_response":
        return "finalize"
    if action in ("gather_evidence", "run_specialist"):
        return "evidence"
    if action == "compress_events":
        return "compress"
    if action == "run_swarm":
        return "swarm"
    if action == "perform_rca":
        return "rca"
    return "finalize"


def build_supervised_graph() -> StateGraph:
    """Build the ReAct supervised investigation graph.

    The supervisor node decides the next action; after each action the graph
    re-enters the supervisor for another observe→reason→act cycle.
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("gather_evidence", gather_evidence_node)
    graph.add_node("compress_events", compress_events_node)
    graph.add_node("run_swarm", run_swarm_node)
    graph.add_node("perform_rca", perform_rca_node)
    graph.add_node("finalize_response", finalize_response_node)

    graph.set_entry_point("auto_triage")

    # After auto-triage: if auto-closed → END, else → supervisor.
    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "supervisor"},
    )

    # Supervisor routes to one of the action nodes.
    graph.add_conditional_edges(
        "supervisor",
        _supervisor_route,
        {
            "evidence": "gather_evidence",
            "compress": "compress_events",
            "swarm": "run_swarm",
            "rca": "perform_rca",
            "finalize": "finalize_response",
        },
    )

    # All action nodes loop back to supervisor (except finalize → END).
    graph.add_edge("gather_evidence", "supervisor")
    graph.add_edge("compress_events", "supervisor")
    graph.add_edge("run_swarm", "supervisor")
    graph.add_edge("perform_rca", "supervisor")
    graph.add_edge("finalize_response", END)

    return graph.compile()


# Lazy-init: only compile the supervised graph when the feature flag is on.
_supervised_graph_cache = None


def get_supervised_graph():
    """Return the supervised investigation graph (compiled on first call)."""
    global _supervised_graph_cache  # noqa: PLW0603
    if _supervised_graph_cache is None:
        _supervised_graph_cache = build_supervised_graph()
    return _supervised_graph_cache

