"""
Agent service REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.graph.runner import run_full_investigation
from app.models.state import AgentTask, InvestigationState

router = APIRouter()

# In-memory run store for status polling. The durable record of every step is
# the Postgres Investigation Ledger (written by the shared graph runner) — this
# dict is only the fast local status cache for GET /investigations/{run_id}.
_runs: dict[str, dict] = {}


class InvestigationRequest(BaseModel):
    incident_id: UUID
    tenant_id: UUID
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    task: AgentTask = AgentTask.INVESTIGATION


class InvestigationResponse(BaseModel):
    run_id: UUID
    status: str
    message: str


async def _run_investigation(run_id: str, state: InvestigationState) -> None:
    """Run investigation in background and store results.

    Uses the SAME durable graph runner as the Kafka auto-triage worker
    (issue #569), so manual and automated investigations share one
    orchestration implementation and both persist every step to the ledger.
    """
    try:
        result = await run_full_investigation(state)
        _runs[run_id] = {
            "status": "completed",
            "result": result.to_dict(),
            "completed_at": datetime.utcnow().isoformat(),
        }
    except Exception as exc:  # noqa: BLE001 — surface failure via the status cache
        _runs[run_id] = {"status": "failed", "error": str(exc)}


@router.post("/investigations", response_model=InvestigationResponse)
async def start_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
):
    """Start a new automated investigation for an incident."""
    run_id = str(uuid4())
    state = InvestigationState(
        run_id=UUID(run_id),
        incident_id=request.incident_id,
        tenant_id=request.tenant_id,
        task=request.task,
        alert_summary=request.alert_summary,
        raw_alert=request.raw_alert,
    )
    _runs[run_id] = {"status": "running", "started_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_investigation, run_id, state)

    return InvestigationResponse(
        run_id=UUID(run_id),
        status="running",
        message="Investigation started",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str):
    """Get the status and results of an investigation run.

    Two launch surfaces share this poll route: POST /investigations (this
    module) and POST /cases/{id}/investigate (app.api.investigate, whose
    router is registered after this one, so this handler wins the route
    match). Each keeps its own in-memory status cache, so we must consult
    both — otherwise runs launched via /cases/{id}/investigate 404 here and
    the web console silently falls back to demo data.
    """
    run = _runs.get(run_id)
    if not run:
        from app.api import investigate as _investigate  # noqa: PLC0415 — avoid import cycle at module load

        run = _investigate._runs.get(run_id)  # noqa: SLF001 — shared status cache lookup
        if run:
            # Match investigate.py's slim poll contract: reports are served
            # by their dedicated endpoints, not the poll route.
            return {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    return run


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
