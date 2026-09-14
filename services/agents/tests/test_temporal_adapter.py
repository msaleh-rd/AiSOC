"""
Tests for ``app.temporal.adapter.TemporalOrchestratorAdapter`` — the
Temporal-backed streaming adapter used behind ``AISOC_AGENT_TEMPORAL_MODE``.

The real workflow/worker path is covered end-to-end (with a live time-skipping
test server) by ``test_temporal_workflow.py``, gated behind
``AISOC_TEMPORAL_LIVE_TESTS=1`` since it needs network access. Here we
monkeypatch ``app.temporal.client.start_investigation`` so the adapter's own
event-shaping/polling logic (the part that doesn't need a real Temporal
server) is tested in isolation and always runs.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.temporal import adapter as adapter_mod  # noqa: E402
from app.temporal import client as client_mod  # noqa: E402

# Pre-generated UUIDs for deterministic tests — the adapter now validates
# that case_id is a UUID (non-UUID strings hit the early-return error path).
_CASE_1 = str(uuid4())
_CASE_2 = str(uuid4())
_CASE_3 = str(uuid4())
_CASE_4 = str(uuid4())
_TENANT_A = str(uuid4())
_TENANT_B = str(uuid4())
_TENANT_C = str(uuid4())
_TENANT_D = str(uuid4())


class _FakeHandle:
    """Stand-in for ``temporalio.client.WorkflowHandle``."""

    def __init__(self, *, progress_sequence=None, final_result=None, final_exc: Exception | None = None):
        self._progress_sequence = list(progress_sequence or [])
        self._final_result = final_result
        self._final_exc = final_exc

    async def query(self, name: str):  # noqa: ARG002
        if self._progress_sequence:
            return self._progress_sequence.pop(0)
        return {"phase": "completed"}

    async def result(self):
        await asyncio.sleep(0)
        if self._final_exc is not None:
            raise self._final_exc
        return self._final_result


async def _collect(agen) -> list[dict]:
    return [event async for event in agen]


@pytest.mark.asyncio
async def test_stream_kwargs_yields_done_with_rendered_report(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _FakeHandle(
        progress_sequence=[{"phase": "auto_triage"}],
        final_result={
            "incident_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "status": "completed",
            "verdict": "true_positive",
            "confidence": 0.8,
            "findings": ["finding one"],
            "rca_findings": {"root_cause_entity": "user:alice"},
        },
    )

    async def _fake_start(**kwargs):  # noqa: ANN003
        return handle

    monkeypatch.setattr(client_mod, "start_investigation", _fake_start)

    events = await _collect(
        adapter_mod.TemporalOrchestratorAdapter().stream_kwargs(
            case_id=_CASE_1,
            alert_summary="Suspicious login",
            raw_alert={},
            tenant_id=_TENANT_A,
        )
    )

    assert events, "adapter must yield at least the terminal event"
    done_events = [e for e in events if e["type"] == "done"]
    assert len(done_events) == 1
    (done,) = done_events
    assert done["case_id"] == _CASE_1
    state = done["state"]
    assert state["verdict"] == "true_positive"
    assert state["rca_findings"] == {"root_cause_entity": "user:alice"}
    assert "Root Cause Analysis" in state["report_md"] or "root_cause_entity" in state["report_md"]
    assert "<html" in state["report_html"]

    # At least the step observed before completion should surface.
    step_events = [e for e in events if e["type"] == "step"]
    assert all(e["case_id"] == _CASE_1 for e in step_events)


@pytest.mark.asyncio
async def test_stream_kwargs_preserves_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _FakeHandle(final_result={"status": "completed", "verdict": "benign", "confidence": 0.9})
    captured: dict = {}

    async def _fake_start(**kwargs):  # noqa: ANN003
        captured.update(kwargs)
        return handle

    monkeypatch.setattr(client_mod, "start_investigation", _fake_start)

    run_id = uuid4()
    events = await _collect(
        adapter_mod.TemporalOrchestratorAdapter().stream_kwargs(
            case_id=_CASE_2,
            alert_summary="x",
            raw_alert={},
            tenant_id=_TENANT_B,
            run_id=run_id,
        )
    )
    (done,) = [e for e in events if e["type"] == "done"]
    assert done["run_id"] == str(run_id)
    assert captured["run_id"] == run_id
    assert isinstance(captured["run_id"], UUID)


@pytest.mark.asyncio
async def test_stream_kwargs_yields_error_when_start_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_start(**kwargs):  # noqa: ANN003
        raise RuntimeError("temporal server unreachable")

    monkeypatch.setattr(client_mod, "start_investigation", _fake_start)

    events = await _collect(
        adapter_mod.TemporalOrchestratorAdapter().stream_kwargs(
            case_id=_CASE_3,
            alert_summary="x",
            raw_alert={},
            tenant_id=_TENANT_C,
        )
    )

    assert len(events) == 1
    (event,) = events
    assert event["type"] == "error"
    assert "temporal server unreachable" in event["error"]


@pytest.mark.asyncio
async def test_stream_kwargs_yields_error_when_workflow_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _FakeHandle(final_exc=RuntimeError("workflow failed"))

    async def _fake_start(**kwargs):  # noqa: ANN003
        return handle

    monkeypatch.setattr(client_mod, "start_investigation", _fake_start)

    events = await _collect(
        adapter_mod.TemporalOrchestratorAdapter().stream_kwargs(
            case_id=_CASE_4,
            alert_summary="x",
            raw_alert={},
            tenant_id=_TENANT_D,
        )
    )

    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    assert "workflow failed" in error_events[0]["error"]


@pytest.mark.asyncio
async def test_temporal_adapter_with_forensic_package_and_attack_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Temporal adapter renders attack chain from forensic package in final state."""
    handle = _FakeHandle(
        progress_sequence=[{"phase": "gather_evidence"}, {"phase": "finalize_response"}],
        final_result={
            "incident_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "status": "completed",
            "verdict": "true_positive",
            "confidence": 0.95,
            "findings": ["Initial brute force followed by tool download"],
            "rca_findings": {
                "root_cause_entity": "host:inetfw",
                "attack_chain": ["inetfw:brute_force", "linuxshare:donotcry"],
            },
            "forensic_package": {
                "incident_host": "inetfw",
                "attack_chain": ["inetfw:brute_force", "linuxshare:donotcry"],
                "kill_chain_phases": {"initial_access": {"status": "confirmed", "vector": "brute_force"}},
            },
        },
    )

    async def _fake_start(**kwargs):  # noqa: ANN003
        return handle

    monkeypatch.setattr(client_mod, "start_investigation", _fake_start)

    events = await _collect(
        adapter_mod.TemporalOrchestratorAdapter().stream_kwargs(
            case_id=_CASE_1,
            alert_summary="Ransomware campaign",
            raw_alert={},
            tenant_id=_TENANT_A,
        )
    )

    done_events = [e for e in events if e["type"] == "done"]
    assert len(done_events) == 1
    state = done_events[0]["state"]
    assert "## Attack Chain" in state["report_md"]
    assert "inetfw:brute_force" in state["report_md"]
    assert "linuxshare:donotcry" in state["report_md"]
    assert "<html" in state["report_html"]


@pytest.mark.asyncio
async def test_temporal_activities_forensic_execution():
    """Verify Temporal activities execute ForensicsEngine and propagate attack chain."""
    from app.temporal.activities import finalize_response_activity, gather_evidence_activity

    init_state = {
        "run_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "status": "running",
        "alert_summary": "Infiltration attempt",
        "raw_alert": {
            "hostname": "inetfw",
            "description": "Failed password for admin from 192.42.1.174",
            "score": 85.0,
        },
        "findings": [],
        "entities": [],
    }

    # 1. gather_evidence_activity runs deterministic forensics
    ev_state = await gather_evidence_activity(init_state)
    assert "forensic_package" in ev_state
    assert len(ev_state["forensic_package"]["attack_chain"]) > 0
    assert any("Forensic attack chain:" in f for f in ev_state["findings"])

    # 2. finalize_response_activity propagates attack_chain to rca_findings
    fin_state = await finalize_response_activity(ev_state)
    assert fin_state["status"] == "completed"
    assert fin_state["rca_findings"]["attack_chain"] == ev_state["forensic_package"]["attack_chain"]

