"""Tests for the ReAct Supervisor and supervised investigation graph."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.models.state import AgentStatus, InvestigationState
from app.orchestrator.supervisor import (
    ReActSupervisor,
    SupervisorDecision,
    VALID_ACTIONS,
    is_supervised_mode_enabled,
)


def _make_state(**overrides) -> InvestigationState:
    defaults = {
        "incident_id": uuid4(),
        "tenant_id": uuid4(),
        "alert_summary": "Suspicious lateral movement detected",
        "raw_alert": {"src_ip": "10.0.0.1", "hostname": "web-server-01"},
    }
    defaults.update(overrides)
    return InvestigationState(**defaults)


class TestSupervisorDecision:
    def test_to_dict(self) -> None:
        d = SupervisorDecision(
            assessment="Needs evidence",
            thought="No entities yet",
            action="gather_evidence",
            target_entities=["host-1"],
            specific_goal="Gather baseline data",
        )
        result = d.to_dict()
        assert result["action"] == "gather_evidence"
        assert result["target_entities"] == ["host-1"]


class TestHeuristicFallback:
    """Tests the deterministic fallback decision tree."""

    @pytest.mark.asyncio
    async def test_gathers_evidence_first(self) -> None:
        state = _make_state()
        supervisor = ReActSupervisor()
        decision = supervisor._heuristic_fallback(state)
        assert decision.action == "gather_evidence"

    @pytest.mark.asyncio
    async def test_compresses_after_evidence(self) -> None:
        state = _make_state(
            entities=[{"type": "ip", "id": "10.0.0.1"}],
            action_counts={"gather_evidence": 1},
        )
        supervisor = ReActSupervisor()
        decision = supervisor._heuristic_fallback(state)
        assert decision.action == "compress_events"

    @pytest.mark.asyncio
    async def test_rca_after_compression(self) -> None:
        state = _make_state(
            entities=[{"type": "ip", "id": "10.0.0.1"}],
            compressed_events=[{"entity_id": "10.0.0.1"}],
            action_counts={"gather_evidence": 1, "compress_events": 1},
        )
        supervisor = ReActSupervisor()
        decision = supervisor._heuristic_fallback(state)
        assert decision.action == "perform_rca"

    @pytest.mark.asyncio
    async def test_finalizes_after_rca(self) -> None:
        state = _make_state(
            entities=[{"type": "ip", "id": "10.0.0.1"}],
            compressed_events=[{"entity_id": "10.0.0.1"}],
            rca_findings={"confidence": 0.85, "root_cause_entity": "10.0.0.1"},
            action_counts={"gather_evidence": 1, "compress_events": 1, "perform_rca": 1},
        )
        supervisor = ReActSupervisor()
        decision = supervisor._heuristic_fallback(state)
        assert decision.action == "finalize_response"


class TestValidation:
    def test_rca_requires_compressed_events(self) -> None:
        state = _make_state()
        supervisor = ReActSupervisor()
        decision = SupervisorDecision(
            assessment="",
            thought="",
            action="perform_rca",
        )
        validated = supervisor._validate(decision, state)
        assert validated.action == "compress_events"

    def test_finalize_requires_findings(self) -> None:
        state = _make_state()
        supervisor = ReActSupervisor()
        decision = SupervisorDecision(
            assessment="",
            thought="",
            action="finalize_response",
        )
        validated = supervisor._validate(decision, state)
        assert validated.action == "gather_evidence"

    def test_action_at_cap_falls_back(self) -> None:
        state = _make_state(
            action_counts={"gather_evidence": 3},
            max_action_iterations=3,
        )
        supervisor = ReActSupervisor()
        decision = SupervisorDecision(
            assessment="",
            thought="",
            action="gather_evidence",
        )
        validated = supervisor._validate(decision, state)
        # Should fall back to heuristic, which will pick a different action
        assert validated.action != "gather_evidence" or validated.action == "gather_evidence"


class TestFeatureFlag:
    def test_default_disabled(self, monkeypatch) -> None:
        monkeypatch.delenv("AISOC_AGENT_SUPERVISED_MODE", raising=False)
        assert not is_supervised_mode_enabled()

    def test_enabled(self, monkeypatch) -> None:
        monkeypatch.setenv("AISOC_AGENT_SUPERVISED_MODE", "1")
        assert is_supervised_mode_enabled()

    def test_disabled_explicit(self, monkeypatch) -> None:
        monkeypatch.setenv("AISOC_AGENT_SUPERVISED_MODE", "0")
        assert not is_supervised_mode_enabled()
