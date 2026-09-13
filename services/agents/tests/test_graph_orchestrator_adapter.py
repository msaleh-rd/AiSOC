"""
Tests for ``app.graph.adapter.GraphOrchestratorAdapter`` — the LangGraph
pipeline's investigator-compatible streaming adapter.

The graph runner (``run_full_investigation``) only returns a final state
(no per-node stream), so the adapter's contract is: exactly one terminal
event (``done`` on success, ``error`` on failure/exception), carrying a
rendered ``report_md`` / ``report_html`` plus the full state dump —
including RCA / supervisor / compression fields the fixed and supervised
graphs populate.

``run_full_investigation`` itself (ledger writes, LangGraph execution) is
exercised by ``tests/test_graph_runner.py``; here we monkeypatch it so the
adapter's own event-shaping logic is tested in isolation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.graph import adapter as adapter_mod  # noqa: E402
from app.models.state import AgentStatus, InvestigationState  # noqa: E402


def _build_state(**overrides) -> InvestigationState:
    base = {
        "incident_id": UUID("22222222-2222-2222-2222-222222222222"),
        "tenant_id": UUID("33333333-3333-3333-3333-333333333333"),
        "alert_summary": "Suspicious login from foreign IP",
        "status": AgentStatus.COMPLETED,
        "verdict": "true_positive",
        "confidence": 0.8,
        "findings": ["finding one"],
        "rca_findings": {
            "root_cause_entity": "user:alice@example.com",
            "attack_type": "credential_compromise",
            "confidence": 0.9,
        },
        "supervisor_history": [{"action": "gather_evidence"}],
        "compressed_events": [{"summary": "compressed event"}],
    }
    base.update(overrides)
    return InvestigationState(**base)


async def _collect(agen) -> list[dict]:
    return [event async for event in agen]


@pytest.mark.asyncio
async def test_stream_kwargs_yields_done_with_full_state(monkeypatch: pytest.MonkeyPatch) -> None:
    result_state = _build_state()

    async def _fake_run(state, **kwargs):  # noqa: ANN001, ARG001
        return result_state

    monkeypatch.setattr(adapter_mod, "run_full_investigation", _fake_run)

    events = await _collect(
        adapter_mod.GraphOrchestratorAdapter().stream_kwargs(
            case_id="case-1",
            alert_summary="Suspicious login",
            raw_alert={"src_ip": "203.0.113.42"},
            tenant_id="tenant-a",
        )
    )

    assert len(events) == 1
    (event,) = events
    assert event["type"] == "done"
    assert event["case_id"] == "case-1"
    state = event["state"]
    assert state["verdict"] == "true_positive"
    assert state["rca_findings"]["root_cause_entity"] == "user:alice@example.com"
    assert state["supervisor_history"] == [{"action": "gather_evidence"}]
    assert state["compressed_events"] == [{"summary": "compressed event"}]
    assert "root_cause_entity" in state["report_md"] or "Root Cause Analysis" in state["report_md"]
    assert "<html" in state["report_html"]


@pytest.mark.asyncio
async def test_stream_kwargs_coerces_run_id_and_preserves_caller_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    result_state = _build_state()
    captured: dict = {}

    async def _fake_run(state, **kwargs):  # noqa: ANN001, ARG001
        captured["state"] = state
        return result_state

    monkeypatch.setattr(adapter_mod, "run_full_investigation", _fake_run)

    run_id = uuid4()
    events = await _collect(
        adapter_mod.GraphOrchestratorAdapter().stream_kwargs(
            case_id="not-a-uuid-case-slug",
            alert_summary="x",
            raw_alert={},
            tenant_id="not-a-uuid-tenant",
            run_id=run_id,
        )
    )
    (event,) = events
    assert event["run_id"] == str(run_id)
    assert event["case_id"] == "not-a-uuid-case-slug"
    # The internal state coerces the slug to a deterministic UUID.
    assert isinstance(captured["state"].incident_id, UUID)
    assert isinstance(captured["state"].tenant_id, UUID)
    assert captured["state"].run_id == run_id


@pytest.mark.asyncio
async def test_stream_kwargs_yields_error_event_on_failed_status(monkeypatch: pytest.MonkeyPatch) -> None:
    failed_state = _build_state(status=AgentStatus.FAILED, error="budget exceeded")

    async def _fake_run(state, **kwargs):  # noqa: ANN001, ARG001
        return failed_state

    monkeypatch.setattr(adapter_mod, "run_full_investigation", _fake_run)

    events = await _collect(
        adapter_mod.GraphOrchestratorAdapter().stream_kwargs(
            case_id="case-2",
            alert_summary="x",
            raw_alert={},
            tenant_id="tenant-b",
        )
    )

    assert len(events) == 1
    (event,) = events
    assert event["type"] == "error"
    assert event["error"] == "budget exceeded"
    assert event["state"]["status"] == "failed"


@pytest.mark.asyncio
async def test_stream_kwargs_yields_error_event_on_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_run(state, **kwargs):  # noqa: ANN001, ARG001
        raise RuntimeError("graph blew up")

    monkeypatch.setattr(adapter_mod, "run_full_investigation", _fake_run)

    events = await _collect(
        adapter_mod.GraphOrchestratorAdapter().stream_kwargs(
            case_id="case-3",
            alert_summary="x",
            raw_alert={},
            tenant_id="tenant-c",
        )
    )

    assert len(events) == 1
    (event,) = events
    assert event["type"] == "error"
    assert "graph blew up" in event["error"]
