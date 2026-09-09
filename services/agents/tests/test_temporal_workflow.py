"""
Tests for ``app.temporal.workflows.InvestigationWorkflow`` — Phase 5 Temporal
overlay.

Uses ``temporalio.testing.WorkflowEnvironment`` (the SDK's bundled
time-skipping test server) so these tests never require a real Temporal
cluster. The bundled test server binary is downloaded and cached on first
use, which needs outbound network access — so this whole module is marked
``integration`` (same convention as the Kafka/Neo4j/Postgres integration
tests registered in pyproject.toml) and, more importantly, is skipped
outright unless ``AISOC_TEMPORAL_LIVE_TESTS=1`` is set. The download can
hang rather than fail fast when the network is unreachable/filtered (no DNS
error, just a stalled connect), and unlike a slow-but-finite test, a hang
would block an entire ``pytest`` run — the explicit opt-in keeps default
``pytest tests/`` runs (in this repo's sandboxes and most CI runners without
egress) fast and hang-proof. Enable it in an environment known to have
network access to verify real coverage end-to-end.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

if not os.environ.get("AISOC_TEMPORAL_LIVE_TESTS"):
    pytest.skip(
        "Temporal live workflow tests need to download the bundled test-server "
        "binary on first use, which can hang rather than fail fast without "
        "network access. Set AISOC_TEMPORAL_LIVE_TESTS=1 to enable them.",
        allow_module_level=True,
    )

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

temporalio = pytest.importorskip("temporalio")
from temporalio.client import Client  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402

from app.temporal.activities import (  # noqa: E402
    auto_triage_activity,
    compress_events_activity,
    finalize_response_activity,
    gather_evidence_activity,
    perform_rca_activity,
    run_swarm_activity,
    triage_activity,
)
from app.temporal.workflows import InvestigationWorkflow  # noqa: E402

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

_ACTIVITIES = [
    auto_triage_activity,
    triage_activity,
    gather_evidence_activity,
    compress_events_activity,
    run_swarm_activity,
    perform_rca_activity,
    finalize_response_activity,
]


@pytest.fixture
async def temporal_env():
    env = await WorkflowEnvironment.start_time_skipping()
    try:
        yield env
    finally:
        await env.shutdown()


def _request(**overrides) -> dict:
    base = {
        "incident_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "alert_summary": "Suspicious login from foreign IP",
        "raw_alert": {"src_ip": "203.0.113.42", "user": "alice@example.com"},
    }
    base.update(overrides)
    return base


async def test_workflow_runs_full_pipeline_and_completes(temporal_env: WorkflowEnvironment):
    task_queue = f"tq-{uuid.uuid4()}"
    client: Client = temporal_env.client

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[InvestigationWorkflow],
        activities=_ACTIVITIES,
    ):
        result = await client.execute_workflow(
            InvestigationWorkflow.run,
            _request(),
            id=f"wf-{uuid.uuid4()}",
            task_queue=task_queue,
        )

    assert result["status"] == "completed"
    assert isinstance(result.get("findings"), list)
    assert any("finalized" in f.lower() for f in result["findings"])


async def test_workflow_reports_progress_via_query(temporal_env: WorkflowEnvironment):
    task_queue = f"tq-{uuid.uuid4()}"
    client: Client = temporal_env.client

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[InvestigationWorkflow],
        activities=_ACTIVITIES,
    ):
        handle = await client.start_workflow(
            InvestigationWorkflow.run,
            _request(),
            id=f"wf-{uuid.uuid4()}",
            task_queue=task_queue,
        )
        result = await handle.result()
        # Progress is queryable at any point; after completion it must report
        # the terminal phase and a verdict/confidence sourced from real state.
        progress = await handle.query(InvestigationWorkflow.get_progress)
        assert progress["phase"] == "completed"
        assert progress["findings_count"] == len(result["findings"])


async def test_workflow_skips_full_pipeline_when_auto_triage_closes(
    temporal_env: WorkflowEnvironment, monkeypatch: pytest.MonkeyPatch
):
    """When auto-triage auto-closes the alert, the workflow must not run the
    remaining phases (mirrors the LangGraph pipeline's early-exit contract)."""
    from app.graph import workflow as graph_workflow_mod

    calls: list[str] = []

    async def _fake_auto_triage(state: dict) -> dict:
        calls.append("auto_triage")
        s = dict(state)
        s["status"] = "completed"
        s["verdict"] = "false_positive"
        s["confidence"] = 0.95
        s["findings"] = ["Auto-closed: benign"]
        return s

    async def _tracking(name: str, state: dict) -> dict:
        calls.append(name)
        return state

    monkeypatch.setattr(graph_workflow_mod, "auto_triage_node", _fake_auto_triage)

    task_queue = f"tq-{uuid.uuid4()}"
    client: Client = temporal_env.client

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[InvestigationWorkflow],
        activities=_ACTIVITIES,
    ):
        result = await client.execute_workflow(
            InvestigationWorkflow.run,
            _request(),
            id=f"wf-{uuid.uuid4()}",
            task_queue=task_queue,
        )

    assert result["status"] == "completed"
    assert result["verdict"] == "false_positive"
    assert calls == ["auto_triage"], "no further phases should run after an auto-close"


async def test_workflow_hitl_approval_gate_blocks_until_signal(temporal_env: WorkflowEnvironment, monkeypatch: pytest.MonkeyPatch):
    """A proposed action requiring approval must pause the workflow until the
    ``approve`` signal arrives, then reflect the reviewer's decision."""
    from app.graph import workflow as graph_workflow_mod

    async def _fake_finalize(state: dict) -> dict:
        s = dict(state)
        s["status"] = "completed"
        s.setdefault("findings", []).append("Investigation finalized by supervisor")
        return s

    async def _fake_perform_rca(state: dict) -> dict:
        s = dict(state)
        s["confidence"] = 0.9  # clears the reinvestigation loop on first pass
        s["proposed_actions"] = [{"action_type": "disable_user", "requires_approval": True}]
        return s

    monkeypatch.setattr(graph_workflow_mod, "finalize_response_node", _fake_finalize)
    monkeypatch.setattr(graph_workflow_mod, "perform_rca_node", _fake_perform_rca)

    task_queue = f"tq-{uuid.uuid4()}"
    client: Client = temporal_env.client

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[InvestigationWorkflow],
        activities=_ACTIVITIES,
    ):
        handle = await client.start_workflow(
            InvestigationWorkflow.run,
            _request(),
            id=f"wf-{uuid.uuid4()}",
            task_queue=task_queue,
        )

        # Give the workflow a moment to reach the approval gate.
        async def _awaiting() -> bool:
            progress = await handle.query(InvestigationWorkflow.get_progress)
            return bool(progress["awaiting_approval"])

        for _ in range(50):
            if await _awaiting():
                break
            await temporal_env.sleep(0.1)
        assert await _awaiting(), "workflow never reached the approval gate"

        await handle.signal(InvestigationWorkflow.approve, True)
        result = await handle.result()

    assert result["status"] == "completed"
    assert result["proposed_actions"] == [{"action_type": "disable_user", "requires_approval": True}]
