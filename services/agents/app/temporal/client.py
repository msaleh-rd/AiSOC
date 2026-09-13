"""Temporal client helpers — start/observe the durable investigation workflow.

Kept free of any module-level ``temporalio`` import so importing this module
(e.g. from :mod:`app.temporal.adapter`) never requires the optional
dependency to be installed; the import only happens inside the functions
that actually need a live client.
"""

from __future__ import annotations

import os
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from temporalio.client import Client, WorkflowHandle

TASK_QUEUE = "aisoc-investigations"
WORKFLOW_NAME = "InvestigationWorkflow"


def temporal_target_host() -> str:
    """Return the Temporal frontend address (``host:port``), default off-cluster."""
    return os.environ.get("AISOC_TEMPORAL_HOST", "localhost:7233")


async def get_client() -> "Client":
    """Connect a fresh Temporal client.

    The SDK's ``Client`` is cheap to construct and pools its gRPC channel
    internally, so a new client per call is fine here (no module-level
    singleton to manage lifecycle for).
    """
    from temporalio.client import Client

    return await Client.connect(temporal_target_host())


async def start_investigation(
    *,
    run_id: uuid.UUID,
    incident_id: str,
    tenant_id: str,
    alert_summary: str,
    raw_alert: dict[str, Any] | None = None,
) -> "WorkflowHandle":
    """Start an ``InvestigationWorkflow`` execution keyed by ``run_id``.

    Using ``run_id`` as the Temporal workflow id makes the start idempotent:
    Temporal rejects a duplicate start against a still-running workflow id
    with ``WorkflowAlreadyStartedError``, the same idempotency contract
    ``ledger_module.start_run``'s ``ON CONFLICT DO NOTHING`` gives the
    in-process graph runner for re-entrant runs.
    """
    client = await get_client()
    return await client.start_workflow(
        WORKFLOW_NAME,
        {
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "tenant_ref": tenant_id,
            "alert_summary": alert_summary,
            "raw_alert": raw_alert or {},
        },
        id=str(run_id),
        task_queue=TASK_QUEUE,
    )
