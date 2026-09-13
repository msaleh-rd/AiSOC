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
            case_id="case-1",
            alert_summary="Suspicious login",
            raw_alert={},
            tenant_id="tenant-a",
        )
    )

    assert events, "adapter must yield at least the terminal event"
    done_events = [e for e in events if e["type"] == "done"]
    assert len(done_events) == 1
    (done,) = done_events
    assert done["case_id"] == "case-1"
    state = done["state"]
    assert state["verdict"] == "true_positive"
    assert state["rca_findings"] == {"root_cause_entity": "user:alice"}
    assert "Root Cause Analysis" in state["report_md"] or "root_cause_entity" in state["report_md"]
    assert "<html" in state["report_html"]

    # At least the step observed before completion should surface.
    step_events = [e for e in events if e["type"] == "step"]
    assert all(e["case_id"] == "case-1" for e in step_events)


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
            case_id="case-2",
            alert_summary="x",
            raw_alert={},
            tenant_id="tenant-b",
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
            case_id="case-3",
            alert_summary="x",
            raw_alert={},
            tenant_id="tenant-c",
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
            case_id="case-4",
            alert_summary="x",
            raw_alert={},
            tenant_id="tenant-d",
        )
    )

    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    assert "workflow failed" in error_events[0]["error"]
