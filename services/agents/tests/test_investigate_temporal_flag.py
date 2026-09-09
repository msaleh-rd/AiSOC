"""
Temporal overlay — ``/investigate`` orchestrator selection via
``AISOC_AGENT_TEMPORAL_MODE``.

Mirrors ``test_investigate_graph_flag.py``'s coverage for the fourth (and
highest-priority) orchestrator option: the durable Temporal workflow exposed
via :class:`app.temporal.adapter.TemporalOrchestratorAdapter`. Also pins the
full priority order: temporal > graph > router > investigator.
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
TEMPORAL_FLAG = investigate_mod.USE_TEMPORAL_FLAG


def test_temporal_flag_defaults_off_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TEMPORAL_FLAG, raising=False)
    assert investigate_mod.is_temporal_investigate_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "enabled"])
def test_temporal_flag_truthy_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(TEMPORAL_FLAG, value)
    assert investigate_mod.is_temporal_investigate_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "disabled", "anything-else"])
def test_temporal_flag_falsey_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(TEMPORAL_FLAG, value)
    assert investigate_mod.is_temporal_investigate_enabled() is False


@pytest.fixture
def patched_orchestrators(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = {"investigator": [], "router": [], "graph": [], "temporal": []}

    async def _empty() -> Any:
        if False:  # pragma: no cover - generator stub
            yield {}

    def _make(name: str):
        def _fake(**kwargs: Any):
            calls[name].append(kwargs)
            return _empty()

        return _fake

    monkeypatch.setattr(investigate_mod._orch, "stream", _make("investigator"), raising=True)
    monkeypatch.setattr(investigate_mod._router_orch, "stream_kwargs", _make("router"), raising=True)
    monkeypatch.setattr(investigate_mod._graph_orch, "stream_kwargs", _make("graph"), raising=True)
    monkeypatch.setattr(investigate_mod._temporal_orch, "stream_kwargs", _make("temporal"), raising=True)
    return calls


def _exhaust(stream: Any) -> None:
    async def _go() -> None:
        async for _ in stream:
            pass

    asyncio.run(_go())


def test_dispatch_uses_temporal_when_flag_set(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.delenv(ROUTER_FLAG, raising=False)
    monkeypatch.delenv(GRAPH_FLAG, raising=False)
    monkeypatch.setenv(TEMPORAL_FLAG, "1")

    run_id = uuid4()
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-temporal",
            alert_summary="Durable investigation",
            raw_alert={"src_host": "db-02"},
            tenant_id="tenant-t",
            run_id=run_id,
        )
    )

    assert patched_orchestrators["temporal"], "temporal path should fire"
    assert not patched_orchestrators["graph"]
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["investigator"]
    (call,) = patched_orchestrators["temporal"]
    assert call == {
        "case_id": "case-temporal",
        "alert_summary": "Durable investigation",
        "raw_alert": {"src_host": "db-02"},
        "tenant_id": "tenant-t",
        "run_id": run_id,
    }


@pytest.mark.parametrize(
    "flags_on",
    [
        {"temporal", "graph", "router"},
        {"temporal", "graph"},
        {"temporal", "router"},
        {"temporal"},
    ],
)
def test_temporal_flag_wins_over_all_others(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
    flags_on: set[str],
) -> None:
    """Temporal is the most specific/newest opt-in — it must win whenever set,
    regardless of which other flags are also on."""
    monkeypatch.setenv(TEMPORAL_FLAG, "1") if "temporal" in flags_on else monkeypatch.delenv(TEMPORAL_FLAG, raising=False)
    monkeypatch.setenv(GRAPH_FLAG, "1") if "graph" in flags_on else monkeypatch.delenv(GRAPH_FLAG, raising=False)
    monkeypatch.setenv(ROUTER_FLAG, "1") if "router" in flags_on else monkeypatch.delenv(ROUTER_FLAG, raising=False)

    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-x",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    assert patched_orchestrators["temporal"]
    assert not patched_orchestrators["graph"]
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["investigator"]


def test_dispatch_falls_through_to_graph_when_temporal_off(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.delenv(TEMPORAL_FLAG, raising=False)
    monkeypatch.setenv(GRAPH_FLAG, "1")

    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case-y",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    assert patched_orchestrators["graph"]
    assert not patched_orchestrators["temporal"]
    assert not patched_orchestrators["router"]
    assert not patched_orchestrators["investigator"]
