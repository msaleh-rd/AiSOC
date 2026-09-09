"""Data models for the 7-Stage Noise Compression Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique reference."""

    technique_id: str
    technique_name: str = ""
    tactic_name: str = ""


@dataclass
class CorrelatedEvent:
    """Normalised event flowing through the compression pipeline.

    This is the internal representation — raw OCSF events, alert dicts, and
    fusion outputs are all normalised into ``CorrelatedEvent`` before entering
    stage 1.
    """

    timestamp: datetime
    entity_id: str
    event_type: str
    action: str
    risk_score: float = 0.0
    confidence: float = 0.5
    mitre_technique: MitreTechnique | None = None
    raw_events: list[dict[str, Any]] = field(default_factory=list)
    cluster_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "entity_id": self.entity_id,
            "event_type": self.event_type,
            "action": self.action,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
        }
        if self.mitre_technique:
            d["mitre_technique_id"] = self.mitre_technique.technique_id
            d["mitre_technique_name"] = self.mitre_technique.technique_name
            d["mitre_tactic"] = self.mitre_technique.tactic_name
        if self.cluster_id:
            d["cluster_id"] = self.cluster_id
        return d


@dataclass
class StageMetrics:
    """Per-stage reduction metrics for transparency and debugging."""

    name: str
    input_count: int
    output_count: int
    reduction_pct: float
    skill: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "reduction_pct": self.reduction_pct,
            "skill": self.skill,
        }


@dataclass
class CompressedPackage:
    """Final output of the compression pipeline."""

    investigation_id: str
    original_event_count: int
    compressed_event_count: int
    compression_ratio: float
    events: list[CorrelatedEvent]
    timeline: list[dict[str, Any]]
    attack_graph: dict[str, list[str]]
    detected_patterns: list[dict[str, Any]]
    abstractions: list[CorrelatedEvent]
    risk_score: float
    confidence: float
    created_at: datetime
    stage_metrics: list[StageMetrics]

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "original_event_count": self.original_event_count,
            "compressed_event_count": self.compressed_event_count,
            "compression_ratio": round(self.compression_ratio, 2),
            "risk_score": round(self.risk_score, 4),
            "confidence": round(self.confidence, 4),
            "created_at": self.created_at.isoformat(),
            "timeline": self.timeline,
            "attack_graph": self.attack_graph,
            "detected_patterns": self.detected_patterns,
            "stage_metrics": [m.to_dict() for m in self.stage_metrics],
            "events": [e.to_dict() for e in self.events],
        }
