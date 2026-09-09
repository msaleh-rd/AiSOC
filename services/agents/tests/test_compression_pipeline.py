"""Tests for the 7-stage noise compression pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.compression.models import CompressedPackage, CorrelatedEvent, MitreTechnique, StageMetrics
from app.compression.pipeline import CompressionPipeline
from app.compression.stages import (
    AbstractionEngine,
    BehavioralFilter,
    EntityCorrelator,
    EventDeduplicator,
    GraphAnalyzer,
    RiskScorer,
    TemporalFilter,
    normalise_event,
)


def _make_event(
    entity: str = "host-1",
    action: str = "process_created",
    risk: float = 0.5,
    minutes_offset: int = 0,
    event_type: str = "system",
) -> CorrelatedEvent:
    return CorrelatedEvent(
        timestamp=datetime(2024, 1, 15, 14, 0) + timedelta(minutes=minutes_offset),
        entity_id=entity,
        event_type=event_type,
        action=action,
        risk_score=risk,
        confidence=0.8,
    )


class TestTemporalFilter:
    def test_filters_outside_window(self) -> None:
        incident_time = datetime(2024, 1, 15, 14, 0)
        events = [
            _make_event(minutes_offset=-120),  # 2 hours before — outside
            _make_event(minutes_offset=-30),   # 30 min before — inside
            _make_event(minutes_offset=0),     # at incident time
            _make_event(minutes_offset=15),    # 15 min after — inside
            _make_event(minutes_offset=60),    # 1 hour after — outside
        ]
        tf = TemporalFilter(window_before_minutes=60, window_after_minutes=30)
        filtered, reduction = tf.filter_events(events, incident_time)
        assert len(filtered) == 3
        assert reduction > 0

    def test_empty_events(self) -> None:
        tf = TemporalFilter()
        filtered, reduction = tf.filter_events([])
        assert filtered == []
        assert reduction == 0.0

    def test_safety_net_never_empty(self) -> None:
        """When all events would be filtered, keep all."""
        incident_time = datetime(2024, 1, 15, 14, 0)
        events = [_make_event(minutes_offset=-9999)]
        tf = TemporalFilter(window_before_minutes=1, window_after_minutes=1)
        filtered, _ = tf.filter_events(events, incident_time)
        assert len(filtered) == 1


class TestEntityCorrelator:
    def test_groups_by_entity(self) -> None:
        events = [
            _make_event(entity="host-1", risk=0.3),
            _make_event(entity="host-1", risk=0.8),
            _make_event(entity="host-2", risk=0.5),
        ]
        ec = EntityCorrelator()
        correlated, reduction = ec.correlate_events(events)
        assert len(correlated) == 2  # 2 entities
        # The representative for host-1 should have risk 0.8 (highest).
        h1 = [e for e in correlated if e.entity_id == "host-1"][0]
        assert h1.risk_score == 0.8

    def test_empty(self) -> None:
        ec = EntityCorrelator()
        result, red = ec.correlate_events([])
        assert result == []


class TestBehavioralFilter:
    def test_keeps_anomalous(self) -> None:
        events = [
            _make_event(risk=0.1),
            _make_event(risk=0.5),
            _make_event(risk=0.9),
        ]
        bf = BehavioralFilter(anomaly_threshold=0.3)
        anomalous, reduction = bf.filter_anomalies(events)
        assert len(anomalous) == 2
        assert all(e.risk_score >= 0.3 for e in anomalous)

    def test_safety_net_when_nothing_anomalous(self) -> None:
        events = [_make_event(risk=0.1), _make_event(risk=0.2)]
        bf = BehavioralFilter(anomaly_threshold=0.9)
        anomalous, _ = bf.filter_anomalies(events)
        assert len(anomalous) >= 1


class TestEventDeduplicator:
    def test_deduplicates_same_key(self) -> None:
        events = [
            _make_event(entity="host-1", action="login", risk=0.3),
            _make_event(entity="host-1", action="login", risk=0.8),
            _make_event(entity="host-2", action="login", risk=0.5),
        ]
        ed = EventDeduplicator()
        deduped, reduction = ed.deduplicate(events)
        assert len(deduped) == 2  # host-1|login and host-2|login
        # Keep the higher-risk version.
        h1 = [e for e in deduped if e.entity_id == "host-1"][0]
        assert h1.risk_score == 0.8


class TestGraphAnalyzer:
    def test_detects_lateral_movement(self) -> None:
        events = [
            _make_event(action="smb file access"),
            _make_event(action="rdp session started"),
            _make_event(action="normal file read"),
        ]
        ga = GraphAnalyzer()
        patterns, _ = ga.analyze_relationships(events)
        lateral = [p for p in patterns if p["type"] == "lateral_movement"]
        assert len(lateral) >= 2


class TestRiskScorer:
    def test_pattern_bonus(self) -> None:
        events = [
            _make_event(entity="host-1", risk=0.5),
            _make_event(entity="host-2", risk=0.5),
        ]
        patterns = [{"type": "lateral_movement", "entity": "host-1"}]
        rs = RiskScorer(max_output=10, pattern_bonus=0.2)
        scored = rs.score_risks(events, patterns)
        h1 = [e for e in scored if e.entity_id == "host-1"][0]
        assert h1.risk_score == 0.7  # 0.5 + 0.2 bonus


class TestAbstractionEngine:
    def test_summarises_groups(self) -> None:
        events = [
            _make_event(entity="host-1", action="login", risk=0.3),
            _make_event(entity="host-1", action="file_access", risk=0.8),
            _make_event(entity="host-2", action="dns_query", risk=0.4),
        ]
        ae = AbstractionEngine()
        abstractions = ae.abstract_events(events)
        assert len(abstractions) == 2
        h1 = [e for e in abstractions if e.entity_id == "host-1"][0]
        assert h1.risk_score == 0.8


class TestNormaliseEvent:
    def test_normalise_raw_alert(self) -> None:
        raw = {
            "timestamp": "2024-01-15T14:00:00Z",
            "src_ip": "10.0.0.1",
            "action": "login_attempt",
            "risk_score": 0.7,
        }
        event = normalise_event(raw)
        assert event.entity_id == "10.0.0.1"
        assert event.action == "login_attempt"
        assert event.risk_score == 0.7

    def test_normalise_ocsf_event(self) -> None:
        raw = {
            "time": "2024-01-15T14:00:00Z",
            "actor": {"user": {"name": "jdoe"}},
            "activity_name": "File Created",
            "type_name": "File System Activity",
        }
        event = normalise_event(raw)
        assert event.entity_id == "jdoe"
        assert event.action == "File Created"


class TestCompressionPipeline:
    def test_full_pipeline(self) -> None:
        """End-to-end compression reduces event count."""
        raw_events = []
        base = datetime(2024, 1, 15, 14, 0)
        for i in range(50):
            raw_events.append({
                "timestamp": (base + timedelta(minutes=i % 30)).isoformat(),
                "src_ip": f"10.0.0.{i % 5 + 1}",
                "action": f"action_{i % 3}",
                "event_type": "system",
                "risk_score": (i % 10) / 10,
            })

        pipeline = CompressionPipeline()
        package = pipeline.compress(raw_events, investigation_id="test-inc")

        assert isinstance(package, CompressedPackage)
        assert package.original_event_count == 50
        assert package.compressed_event_count <= 50
        assert package.compression_ratio >= 1.0
        assert len(package.stage_metrics) == 7
        for m in package.stage_metrics:
            assert isinstance(m, StageMetrics)
            assert m.input_count >= 0
            assert m.output_count >= 0

    def test_empty_events(self) -> None:
        pipeline = CompressionPipeline()
        package = pipeline.compress([], investigation_id="empty")
        assert package.compressed_event_count == 0

    def test_correlated_events_input(self) -> None:
        """Pipeline accepts CorrelatedEvent directly."""
        events = [_make_event(minutes_offset=i) for i in range(10)]
        pipeline = CompressionPipeline()
        package = pipeline.compress(events, investigation_id="pre-normalised")
        assert package.original_event_count == 10
