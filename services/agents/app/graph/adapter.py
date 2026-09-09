"""Investigator-compatible streaming adapter for the LangGraph pipeline.

The ``/api/v1/cases/{case_id}/investigate`` endpoint (``app.api.investigate``)
selects between three orchestrators at call time via environment flags:

* :class:`app.investigator.InvestigatorOrchestrator` — legacy default.
* :class:`app.orchestrator.router.RouterOrchestrator` — four-agent (T2.2),
  behind ``AISOC_INVESTIGATE_USE_ROUTER``.
* :class:`GraphOrchestratorAdapter` (this module) — the LangGraph fixed /
  supervised pipeline (:func:`app.graph.runner.run_full_investigation`),
  behind ``AISOC_INVESTIGATE_USE_GRAPH``.

The graph runner only returns a final :class:`InvestigationState` — its
internal ``_run`` loop already drives ``graph.astream`` node-by-node but
doesn't expose intermediate state to callers — so this adapter synthesises
a single terminal ``done`` event (no interim ``step`` events) rather than a
per-node stream. The event carries a rendered ``report_md`` / ``report_html``
(reusing :func:`app.orchestrator.report.render_router_report`, since both
the router and the graph pipeline share the same ``InvestigationState``
model) plus the full state dump — including the RCA / supervisor / event
compression fields the fixed and supervised graphs populate — so consumers
get those fields for free without any bespoke mapping.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog

from app.graph.runner import run_full_investigation
from app.models.state import AgentStatus, InvestigationState
from app.orchestrator.report import render_router_report

logger = structlog.get_logger()


def _coerce_uuid(value: str) -> uuid.UUID:
    """Coerce a caller-supplied identifier to a UUID.

    Mirrors ``app.orchestrator.router._coerce_uuid``: real UUIDs pass
    through, anything else (e.g. a human-readable case slug) is mapped
    deterministically via ``uuid5`` so the same input always resolves to
    the same identifier.
    """
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return uuid.uuid5(uuid.NAMESPACE_URL, str(value))


class GraphOrchestratorAdapter:
    """Adapts :func:`run_full_investigation` to the investigator streaming contract."""

    async def stream_kwargs(
        self,
        *,
        case_id: str,
        alert_summary: str,
        raw_alert: dict[str, Any] | None = None,
        tenant_id: str = "default",
        run_id: uuid.UUID | None = None,
        topology: str | None = None,  # noqa: ARG002 — accepted for signature parity, unused
    ) -> AsyncIterator[dict[str, Any]]:
        """Run the graph pipeline and yield a single ``done``/``error`` event.

        Matches :meth:`app.orchestrator.router.RouterOrchestrator.stream_kwargs`'s
        signature so ``app.api.investigate._investigate_stream`` can select
        this adapter without changing its call site.
        """
        incident_uuid = _coerce_uuid(case_id)
        tenant_uuid = _coerce_uuid(tenant_id)
        run_uuid = run_id if isinstance(run_id, uuid.UUID) else uuid.uuid4()
        run_id_str = str(run_uuid)

        state = InvestigationState(
            run_id=run_uuid,
            incident_id=incident_uuid,
            tenant_id=tenant_uuid,
            alert_summary=alert_summary,
            raw_alert=raw_alert or {},
        )

        try:
            result = await run_full_investigation(state)
        except Exception as exc:  # noqa: BLE001 — surface as an in-band error event
            logger.exception("graph_adapter.investigation_failed", run_id=run_id_str)
            yield {
                "type": "error",
                "error": str(exc),
                "case_id": case_id,
                "run_id": run_id_str,
            }
            return

        if result.status == AgentStatus.FAILED:
            yield {
                "type": "error",
                "error": result.error or "graph investigation failed",
                "case_id": case_id,
                "run_id": run_id_str,
                "state": result.to_dict(),
            }
            return

        report_md, report_html = render_router_report(result)
        state_dict = result.to_dict()
        state_dict["report_md"] = report_md
        state_dict["report_html"] = report_html
        yield {
            "type": "done",
            "case_id": case_id,
            "run_id": run_id_str,
            "state": state_dict,
        }
