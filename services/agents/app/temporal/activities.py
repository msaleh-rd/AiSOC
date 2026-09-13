"""Temporal activities — thin wrappers around the LangGraph node functions.

Each activity delegates to the same node function the in-process LangGraph
pipeline uses (:mod:`app.graph.workflow`), so investigation logic lives in
exactly one place — Temporal only adds durable orchestration around it. The
node functions already take/return a plain ``dict`` (they convert to/from
:class:`app.models.state.InvestigationState` internally), which happens to
be exactly the shape Temporal's default data converter needs, so no
serialization shim is required.

This module is only imported when Temporal mode is actually used (worker
process, or ``TemporalOrchestratorAdapter`` behind ``AISOC_AGENT_TEMPORAL_MODE``)
— importing ``app.graph.workflow``/``app.temporal.*`` never happens on the
default request path, so a deployment without ``temporalio`` installed is
completely unaffected.
"""

from __future__ import annotations

from typing import Any

from temporalio import activity


@activity.defn(name="auto_triage")
async def auto_triage_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import auto_triage_node

    return await auto_triage_node(state)


@activity.defn(name="triage")
async def triage_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import triage_node

    return await triage_node(state)


@activity.defn(name="gather_evidence")
async def gather_evidence_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import gather_evidence_node

    return await gather_evidence_node(state)


@activity.defn(name="compress_events")
async def compress_events_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import compress_events_node

    return await compress_events_node(state)


@activity.defn(name="run_swarm")
async def run_swarm_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import run_swarm_node

    return await run_swarm_node(state)


@activity.defn(name="perform_rca")
async def perform_rca_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import perform_rca_node

    return await perform_rca_node(state)


@activity.defn(name="finalize_response")
async def finalize_response_activity(state: dict[str, Any]) -> dict[str, Any]:
    from app.graph.workflow import finalize_response_node

    return await finalize_response_node(state)


@activity.defn(name="record_ledger_event")
async def record_ledger_event_activity(payload: dict[str, Any]) -> None:
    """Best-effort append to the Investigation Ledger for one workflow step.

    Mirrors the graph runner's per-node ``ledger_module.record_event`` call
    (see ``app.graph.runner._run``) so Temporal-driven runs show up in the
    same ledger/timeline UI as in-process runs. Never raises — a ledger
    outage must not fail the durable workflow.
    """
    import uuid

    from app.investigator import ledger as ledger_module

    try:
        tenant_uuid = await ledger_module.resolve_tenant(str(payload["tenant_ref"]))
        if tenant_uuid is None:
            return
        await ledger_module.record_event(
            run_id=uuid.UUID(payload["run_id"]),
            tenant_id=tenant_uuid,
            seq=int(payload["seq"]),
            kind="temporal_step",
            agent=str(payload["agent"]),
            summary=str(payload.get("summary", f"temporal activity '{payload['agent']}' completed")),
            payload={"node": str(payload["agent"])},
        )
    except Exception:  # noqa: BLE001 — ledger writes are advisory only
        activity.logger.warning("temporal.ledger_event_failed", extra={"payload": payload})
