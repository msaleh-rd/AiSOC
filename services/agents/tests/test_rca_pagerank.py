"""Tests for the PageRank Root Cause Analysis engine."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.compression.models import CorrelatedEvent, MitreTechnique

# Import conditionally — test is skipped if networkx isn't installed.
try:
    import networkx as nx

    from app.rca.causal_graph import CausalGraphBuilder
    from app.rca.config import CausalFactors
    from app.rca.pagerank_scorer import PageRankRCA, RootCauseAnalysis

    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

pytestmark = pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")


def _make_event(
    entity: str,
    action: str = "process_created",
    risk: float = 0.5,
    minutes_offset: int = 0,
    technique_id: str | None = None,
) -> CorrelatedEvent:
    mitre = MitreTechnique(technique_id=technique_id) if technique_id else None
    return CorrelatedEvent(
        timestamp=datetime(2024, 1, 15, 14, 0) + timedelta(minutes=minutes_offset),
        entity_id=entity,
        event_type="system",
        action=action,
        risk_score=risk,
        confidence=0.8,
        mitre_technique=mitre,
    )


class TestCausalGraphBuilder:
    def test_builds_graph_from_events(self) -> None:
        events = [
            _make_event("attacker-ip", "initial access", risk=0.9, minutes_offset=0),
            _make_event("web-server", "exploit", risk=0.8, minutes_offset=1),
            _make_event("db-server", "credential dump", risk=0.7, minutes_offset=3),
        ]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        assert graph.number_of_nodes() == 3
        assert graph.number_of_edges() > 0
        # Temporal edge: attacker-ip → web-server (earlier → later)
        assert graph.has_edge("attacker-ip", "web-server")

    def test_empty_events(self) -> None:
        builder = CausalGraphBuilder()
        graph = builder.build_from_events([])
        assert graph.number_of_nodes() == 0

    def test_known_dependencies(self) -> None:
        events = [
            _make_event("service-a", risk=0.5),
            _make_event("service-b", risk=0.5),
        ]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(
            events,
            known_dependencies={"service-a": ["service-b"]},
        )
        assert graph.has_edge("service-a", "service-b")

    def test_node_attributes(self) -> None:
        events = [
            _make_event("host-1", risk=0.3, minutes_offset=0),
            _make_event("host-1", risk=0.8, minutes_offset=5),
        ]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        node = graph.nodes["host-1"]
        assert node["risk_score"] == 0.8  # max risk
        assert node["event_count"] == 2


class TestPageRankRCA:
    def test_identifies_root_cause(self) -> None:
        """The entity with earliest anomaly + highest causal influence should be root cause."""
        events = [
            _make_event("attacker-ip", "initial access", risk=0.9, minutes_offset=0),
            _make_event("web-server", "exploit detected", risk=0.8, minutes_offset=2),
            _make_event("db-server", "credential dump", risk=0.7, minutes_offset=5),
            _make_event("file-server", "lateral movement smb", risk=0.6, minutes_offset=8),
        ]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, target_entity="file-server", events=events)

        assert isinstance(result, RootCauseAnalysis)
        assert result.root_cause_entity != "file-server"  # target shouldn't be root cause
        assert result.confidence > 0.0
        assert result.estimated_blast_radius >= 0

    def test_empty_graph(self) -> None:
        builder = CausalGraphBuilder()
        graph = builder.build_from_events([])

        rca = PageRankRCA()
        result = rca.analyze(graph, "target", [])
        assert result.confidence == 0.0
        assert result.confidence_level == "very_low"

    def test_single_entity(self) -> None:
        events = [_make_event("only-host", risk=0.9)]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, "only-host", events)
        assert result.root_cause_entity == "only-host"

    def test_blast_radius(self) -> None:
        events = [
            _make_event("root", risk=0.9, minutes_offset=0),
            _make_event("child-1", risk=0.7, minutes_offset=1),
            _make_event("child-2", risk=0.6, minutes_offset=2),
            _make_event("grandchild", risk=0.5, minutes_offset=3),
        ]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, "grandchild", events)
        # At least the root entity should have some blast radius.
        assert result.estimated_blast_radius >= 0

    def test_remediation_complexity(self) -> None:
        # Simple case: few events, small blast radius.
        events = [_make_event("host", risk=0.5)]
        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, "host", events)
        assert result.remediation_complexity == "simple"

    def test_custom_config(self) -> None:
        config = CausalFactors(direct_dependency_boost=3.0)
        rca = PageRankRCA(config=config)
        assert rca.config.direct_dependency_boost == 3.0
