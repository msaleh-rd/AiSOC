"""Investigator-compatible streaming adapter for the Temporal-backed workflow.

Behind ``AISOC_AGENT_TEMPORAL_MODE`` (default off): starts an
:class:`app.temporal.workflows.InvestigationWorkflow` execution and polls its
queryable progress (``get_progress``) so ``/investigate`` consumers see the
same ``step`` / ``done`` / ``error`` event taxonomy the in-process adapters
emit, while the investigation itself runs durably outside this process.

Requires a running Temporal server + a worker process consuming the
``aisoc-investigations`` task queue (``python -m app.temporal.worker``); see
the ``temporal`` Docker Compose profile. If ``temporalio`` isn't installed,
or the server is unreachable, this adapter yields an explicit ``error``
event rather than silently falling back to another orchestrator — an
operator who opted into Temporal mode must not be told a run "worked" when
it never actually started.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

import structlog

logger = structlog.get_logger()

_POLL_INTERVAL_SECONDS = 2.0


class TemporalOrchestratorAdapter:
    """Adapts the durable Temporal workflow to the investigator streaming contract."""

    async def stream_kwargs(
        self,
        *,
        case_id: str,
        alert_summary: str,
        raw_alert: dict[str, Any] | None = None,
        tenant_id: str = "default",
        run_id: uuid.UUID | None = None,
        topology: str | None = None,  # noqa: ARG002 — signature parity, unused
    ) -> AsyncIterator[dict[str, Any]]:
        from app.temporal.client import start_investigation

        run_uuid = run_id if isinstance(run_id, uuid.UUID) else uuid.uuid4()
        run_id_str = str(run_uuid)

        # InvestigationState requires real UUIDs for incident_id/tenant_id
        # (app.models.state.InvestigationState), but callers may pass a
        # tenant slug/name (e.g. the "default" default) the way every other
        # orchestrator tolerates. Resolve it the same way the ledger does
        # instead of handing a non-UUID string to the workflow, where a
        # permanent validation failure would otherwise retry forever inside
        # the activity rather than failing this request fast.
        try:
            incident_uuid = uuid.UUID(str(case_id))
        except (ValueError, AttributeError, TypeError):
            logger.warning("temporal_adapter.invalid_case_id", case_id=case_id, run_id=run_id_str)
            yield {
                "type": "error",
                "error": (
                    f"Temporal mode requires a UUID case_id, got {case_id!r}. "
                    "This case was not created through the standard case API."
                ),
                "case_id": case_id,
                "run_id": run_id_str,
            }
            return

        resolved_tenant_id = await self._resolve_tenant_uuid(tenant_id)
        if resolved_tenant_id is None:
            logger.warning("temporal_adapter.invalid_tenant_id", tenant_id=tenant_id, run_id=run_id_str)
            yield {
                "type": "error",
                "error": f"Temporal mode could not resolve tenant_id {tenant_id!r} to a known tenant.",
                "case_id": case_id,
                "run_id": run_id_str,
            }
            return

        try:
            handle = await start_investigation(
                run_id=run_uuid,
                incident_id=str(incident_uuid),
                tenant_id=str(resolved_tenant_id),
                alert_summary=alert_summary,
                raw_alert=raw_alert,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("temporal_adapter.start_failed", run_id=run_id_str)
            yield {
                "type": "error",
                "error": f"failed to start Temporal workflow: {exc}",
                "case_id": case_id,
                "run_id": run_id_str,
            }
            return

        result_task = asyncio.ensure_future(handle.result())
        last_phase: str | None = None
        seq = 0
        try:
            while not result_task.done():
                try:
                    progress = await handle.query("get_progress")
                except Exception:  # noqa: BLE001 — query races with completion are expected
                    progress = None
                phase = progress.get("phase") if progress else None
                if phase is not None and phase != last_phase:
                    last_phase = phase
                    seq += 1
                    yield {
                        "type": "step",
                        "seq": seq,
                        "agent": phase,
                        "summary": f"temporal phase '{phase}'",
                        "case_id": case_id,
                        "run_id": run_id_str,
                    }
                await asyncio.wait({result_task}, timeout=_POLL_INTERVAL_SECONDS)

            result = await result_task
        except Exception as exc:  # noqa: BLE001
            logger.exception("temporal_adapter.run_failed", run_id=run_id_str)
            yield {
                "type": "error",
                "error": str(exc),
                "case_id": case_id,
                "run_id": run_id_str,
            }
            return

        result = self._with_rendered_report(result, run_id_str=run_id_str)
        yield {
            "type": "done",
            "case_id": case_id,
            "run_id": run_id_str,
            "state": result,
        }

    @staticmethod
    async def _resolve_tenant_uuid(tenant_ref: str) -> uuid.UUID | None:
        """Resolve a tenant ref (UUID string / slug / name) to its UUID.

        ``InvestigationState.tenant_id`` requires a real UUID, but every
        other orchestrator's ``tenant_id`` default of ``"default"`` is a
        slug, not a UUID. Reuses the same resolver the ledger uses so
        Temporal mode accepts the same inputs as the in-process orchestrators
        instead of failing on the common case.
        """
        try:
            return uuid.UUID(str(tenant_ref))
        except (ValueError, AttributeError, TypeError):
            pass
        try:
            from app.investigator import ledger as ledger_module

            return await ledger_module.resolve_tenant(str(tenant_ref))
        except Exception:  # noqa: BLE001 — best-effort resolution
            logger.debug("temporal_adapter.tenant_resolve_failed", tenant_ref=tenant_ref)
            return None

    @staticmethod
    def _with_rendered_report(result: dict[str, Any], *, run_id_str: str) -> dict[str, Any]:
        """Best-effort ``report_md``/``report_html`` synthesis for the final state.

        Mirrors :class:`app.graph.adapter.GraphOrchestratorAdapter` — both
        share the same :class:`app.models.state.InvestigationState` shape,
        so the same deterministic renderer applies.
        """
        try:
            from app.models.state import InvestigationState
            from app.orchestrator.report import render_router_report

            validated = InvestigationState.model_validate(result)
            report_md, report_html = render_router_report(validated)
            result = dict(result)
            result["report_md"] = report_md
            result["report_html"] = report_html
        except Exception:  # noqa: BLE001 — report rendering is best-effort
            logger.warning("temporal_adapter.report_render_failed", run_id=run_id_str)
        return result
