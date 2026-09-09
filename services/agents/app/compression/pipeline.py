"""CompressionPipeline — orchestrates the 7-stage noise compression engine.

Usage::

    from app.compression.pipeline import CompressionPipeline

    pipeline = CompressionPipeline()
    package = pipeline.compress(
        events=raw_event_dicts,
        investigation_id="INC-2024-001",
        incident_time=datetime(2024, 1, 15, 14, 30),
    )
    print(f"Compressed {package.original_event_count} → {package.compressed_event_count}")
    for m in package.stage_metrics:
        print(f"  {m.name}: {m.input_count} → {m.output_count} ({m.reduction_pct}%)")

Feature flag
============

``AISOC_COMPRESSION_ENABLED`` (env, default ``1``).  When disabled, the
pipeline returns a pass-through package with all events untouched.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from typing import Any

import structlog

from app.compression.models import CompressedPackage, CorrelatedEvent, StageMetrics
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

logger = structlog.get_logger()

_ENABLED_FLAG = "AISOC_COMPRESSION_ENABLED"


def _is_enabled() -> bool:
    raw = os.getenv(_ENABLED_FLAG)
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off", "disabled"}


class CompressionPipeline:
    """7-stage noise compression engine.

    Reduces raw event streams (10,000+) to ~10 critical investigation
    milestones via transparent, staged reduction with per-stage metrics.

    Stages:
        1. Temporal Filter — cluster events around incident time
        2. Entity Correlation — group by shared entities
        3. Behavioral Filter — keep anomalous events
        4. Deduplication — collapse near-identical events
        5. Graph Analysis — identify attack patterns
        6. Risk Scoring — re-score with pattern context, keep top-N
        7. Abstraction — summarise into entity-level groups
    """

    def __init__(
        self,
        *,
        temporal_window_before: int = 60,
        temporal_window_after: int = 30,
        anomaly_threshold: float = 0.3,
        max_risk_output: int = 20,
        pattern_bonus: float = 0.2,
    ) -> None:
        self.temporal_filter = TemporalFilter(
            window_before_minutes=temporal_window_before,
            window_after_minutes=temporal_window_after,
        )
        self.entity_correlator = EntityCorrelator()
        self.behavioral_filter = BehavioralFilter(anomaly_threshold=anomaly_threshold)
        self.deduplicator = EventDeduplicator()
        self.graph_analyzer = GraphAnalyzer()
        self.risk_scorer = RiskScorer(max_output=max_risk_output, pattern_bonus=pattern_bonus)
        self.abstraction_engine = AbstractionEngine()

    def compress(
        self,
        events: list[dict[str, Any]] | list[CorrelatedEvent],
        investigation_id: str = "",
        incident_time: datetime | None = None,
    ) -> CompressedPackage:
        """Run all 7 stages and return a ``CompressedPackage``."""

        # Normalise raw dicts into CorrelatedEvent if needed.
        normalised: list[CorrelatedEvent]
        if events and isinstance(events[0], dict):
            normalised = [normalise_event(e) for e in events]  # type: ignore[arg-type]
        else:
            normalised = list(events)  # type: ignore[arg-type]

        original_count = len(normalised)
        stage_metrics: list[StageMetrics] = []

        if not _is_enabled() or not normalised:
            return self._passthrough_package(normalised, investigation_id, stage_metrics)

        logger.info(
            "compression.pipeline.start",
            investigation_id=investigation_id,
            event_count=original_count,
        )

        # Stage 1: Temporal Filter
        count_before = len(normalised)
        temporal_events, reduction = self.temporal_filter.filter_events(normalised, incident_time)
        stage_metrics.append(StageMetrics(
            name="Temporal Filter",
            input_count=count_before,
            output_count=len(temporal_events),
            reduction_pct=round(reduction * 100, 1),
            skill="temporal-clustering",
        ))

        # Stage 2: Entity Correlation
        count_before = len(temporal_events)
        correlated_events, reduction = self.entity_correlator.correlate_events(temporal_events)
        stage_metrics.append(StageMetrics(
            name="Entity Correlation",
            input_count=count_before,
            output_count=len(correlated_events),
            reduction_pct=round(reduction * 100, 1),
            skill="entity-graph-reduction",
        ))

        # Stage 3: Behavioral Filter
        count_before = len(correlated_events)
        anomalous_events, reduction = self.behavioral_filter.filter_anomalies(correlated_events)
        stage_metrics.append(StageMetrics(
            name="Behavioral Filter",
            input_count=count_before,
            output_count=len(anomalous_events),
            reduction_pct=round(reduction * 100, 1),
            skill="behavioral-anomaly-filter",
        ))

        # Stage 4: Deduplication
        count_before = len(anomalous_events)
        deduped_events, reduction = self.deduplicator.deduplicate(anomalous_events)
        stage_metrics.append(StageMetrics(
            name="Deduplication",
            input_count=count_before,
            output_count=len(deduped_events),
            reduction_pct=round(reduction * 100, 1),
            skill="duplicate-rollup",
        ))

        # Stage 5: Graph Analysis
        count_before = len(deduped_events)
        patterns, reduction = self.graph_analyzer.analyze_relationships(deduped_events)
        pattern_entities = {p.get("entity") for p in patterns if p.get("entity")}
        if pattern_entities:
            graph_events = [
                e for e in deduped_events
                if e.entity_id in pattern_entities or e.risk_score >= 0.4
            ]
        else:
            graph_events = deduped_events
        if not graph_events:
            graph_events = deduped_events
        graph_reduction = (1.0 - len(graph_events) / max(count_before, 1)) if count_before else 0.0
        stage_metrics.append(StageMetrics(
            name="Graph Analysis",
            input_count=count_before,
            output_count=len(graph_events),
            reduction_pct=round(graph_reduction * 100, 1),
            skill="entity-graph-reduction",
        ))

        # Stage 6: Risk Scoring
        count_before = len(graph_events)
        high_risk_events = self.risk_scorer.score_risks(graph_events, patterns)
        stage_metrics.append(StageMetrics(
            name="Risk Scoring",
            input_count=count_before,
            output_count=len(high_risk_events),
            reduction_pct=round((1.0 - len(high_risk_events) / max(count_before, 1)) * 100, 1),
            skill="risk-ranking",
        ))

        # Stage 7: Abstraction
        abstractions = self.abstraction_engine.abstract_events(high_risk_events)
        stage_metrics.append(StageMetrics(
            name="Abstraction",
            input_count=len(high_risk_events),
            output_count=len(abstractions),
            reduction_pct=round((1.0 - len(abstractions) / max(len(high_risk_events), 1)) * 100, 1),
            skill="semantic-summarizer",
        ))

        # Build the compressed package.
        timeline = self._build_timeline(abstractions)
        attack_graph = self._build_attack_graph(patterns)
        risk_score = self._calculate_package_risk(high_risk_events, patterns)
        confidence = self._calculate_confidence(high_risk_events)

        package = CompressedPackage(
            investigation_id=investigation_id,
            original_event_count=original_count,
            compressed_event_count=len(abstractions),
            compression_ratio=original_count / max(len(abstractions), 1),
            events=abstractions,
            timeline=timeline,
            attack_graph=attack_graph,
            detected_patterns=patterns,
            abstractions=abstractions,
            risk_score=risk_score,
            confidence=confidence,
            created_at=datetime.utcnow(),
            stage_metrics=stage_metrics,
        )

        logger.info(
            "compression.pipeline.complete",
            investigation_id=investigation_id,
            original=original_count,
            compressed=len(abstractions),
            ratio=f"{package.compression_ratio:.1f}x",
            risk_score=f"{risk_score:.2f}",
            stages=len(stage_metrics),
        )

        return package

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_timeline(events: list[CorrelatedEvent]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for event in sorted(events, key=lambda e: e.timestamp):
            entry: dict[str, Any] = {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "entity": event.entity_id,
                "action": event.action,
                "risk_score": event.risk_score,
            }
            if event.mitre_technique:
                entry["mitre_tactic"] = event.mitre_technique.tactic_name
                entry["mitre_technique_id"] = event.mitre_technique.technique_id
                entry["mitre_technique_name"] = event.mitre_technique.technique_name
            timeline.append(entry)
        return timeline

    @staticmethod
    def _build_attack_graph(patterns: list[dict[str, Any]]) -> dict[str, list[str]]:
        graph: dict[str, list[str]] = defaultdict(list)
        for pattern in patterns:
            attack_type = pattern.get("type", "unknown")
            entity = pattern.get("entity", "unknown")
            graph[attack_type].append(entity)
        return dict(graph)

    @staticmethod
    def _calculate_package_risk(
        events: list[CorrelatedEvent], patterns: list[dict[str, Any]]
    ) -> float:
        if not events:
            return 0.0
        event_risks = [e.risk_score for e in events]
        event_risk_avg = sum(event_risks) / len(event_risks)
        pattern_risk = min(len(patterns) * 0.1, 1.0)
        return min(1.0, event_risk_avg * 0.6 + pattern_risk * 0.4)

    @staticmethod
    def _calculate_confidence(events: list[CorrelatedEvent]) -> float:
        if not events:
            return 0.0
        return min(1.0, sum(e.confidence for e in events) / len(events))

    @staticmethod
    def _passthrough_package(
        events: list[CorrelatedEvent],
        investigation_id: str,
        stage_metrics: list[StageMetrics],
    ) -> CompressedPackage:
        return CompressedPackage(
            investigation_id=investigation_id,
            original_event_count=len(events),
            compressed_event_count=len(events),
            compression_ratio=1.0,
            events=events,
            timeline=[e.to_dict() for e in events],
            attack_graph={},
            detected_patterns=[],
            abstractions=events,
            risk_score=0.0,
            confidence=0.0,
            created_at=datetime.utcnow(),
            stage_metrics=stage_metrics,
        )
