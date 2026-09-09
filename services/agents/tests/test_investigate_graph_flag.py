"""
Graph pipeline — ``/investigate`` orchestrator selection via
``AISOC_INVESTIGATE_USE_GRAPH``.

Mirrors ``test_investigate_router_flag.py``'s coverage for the third
orchestrator option: the LangGraph fixed/supervised pipeline exposed via
:class:`app.graph.adapter.GraphOrchestratorAdapter`. Also pins the
priority order when multiple flags are set: graph > router > investigator.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api import investigate as investigate_mod  # noqa: E402

ROUTER_FLAG = investigate_mod.USE_ROUTER_FLAG
GRAPH_FLAG = investigate_mod.USE_GRAPH_FLAG


def test_graph_flag_defaults_off_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GRAPH_FLAG, raising=False)
    assert investigate_mod.is_graph_investigate_enabled() is False


@pytest.mark.parametrize(
    "value",
    ["1", "true", "TRUE", "yes", "on", "enabled"],
)
def test_graph_flag_truthy_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(GRAPH_FLAG, value)
    assert investigate_mod.is_graph_investigate_enabled() is True


@pytest.mark.parametrize(
    "value",
    ["", "0", "false", "no", "off", "disabled", "anything-else"],
)
def test_graph_flag_falsey_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(GRAPH_FLAG, value)
    assert investigate_mod.is_graph_investigate_enabled() is False


@pytest.fixture
def patched_orchestrators(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = {"investigator": [], "router": [], "graph": []}

    async def _empty() -> Any:
        if False:  # pragma: no cover - generator stub
            yield {}

    def _fake_investigator_stream(**kwargs: Any):
        calls["investigator"].append(kwargs)
        return _empty()

    def _fake_router_stream_kwargs(**kwargs: Any):
        calls["router"].append(kwargs)
        return _empty()

    def _fake_graph_stream_kwargs(**kwargs: Any):
        calls["graph"].append(kwargs)
        return _empty()

    monkeypatch.setattr(investigate_mod._orch, "stream", _fake_investigator_stream, raising=True)
    monkeypatch.setattr(investigate_mod._router_orch, "stream_kwargs", _fake_router_stream_kwargs, raising=True)
    monkeypatch.setattr(investigate_mod._graph_orch, "stream_kwargs", _fake_graph_stream_kwargs, raising=True)
    return calls


def _exhaust(stream: Any) -> None:
    async def _go() -> None:
        async for _ in stream:
            pass

    asyncio.run(_go())


def test_dispatch_uses_graph_when_flag_set(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.delenv(ROUTER_FLAG, raising=False)
    monkeypatch.setenv(GRAPH_FLAG, "1")

    run_id = uuid4()
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-graph",
            alert_summary="Lateral movement suspected",
            raw_alert={"src_host": "web-01"},
            tenant_id="tenant-g",
            run_id=run_id,
        )
    )

    assert patched_orchestrators["graph"], "graph path should fire"
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["investigator"]
    (call,) = patched_orchestrators["graph"]
    assert call == {
        "case_id": "case-graph",
        "alert_summary": "Lateral movement suspected",
        "raw_alert": {"src_host": "web-01"},
        "tenant_id": "tenant-g",
        "run_id": run_id,
    }


def test_graph_flag_takes_priority_over_router_flag(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    """When both flags are set, the graph pipeline wins (more specific/newer opt-in)."""
    monkeypatch.setenv(ROUTER_FLAG, "1")
    monkeypatch.setenv(GRAPH_FLAG, "1")

    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-both",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    assert patched_orchestrators["graph"], "graph must win when both flags are set"
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["investigator"]


def test_dispatch_still_uses_investigator_when_neither_flag_set(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.delenv(ROUTER_FLAG, raising=False)
    monkeypatch.delenv(GRAPH_FLAG, raising=False)

    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-none",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    assert patched_orchestrators["investigator"]
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["graph"]
