"""Data contracts for deterministic forensic investigation.

Ported and hardened from sxsecurityinvestigator for AiSOC dual-track investigation.
Defines models for MITRE kill-chain phases, attack-stage candidates, collapsed
timeline entries, and the complete forensic investigation package.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AttackStage:
    """An evidence-based attack stage candidate on a specific host."""

    host: str
    artifact: str
    score: float = 0.0
    timestamp: datetime | None = None
    source: str = "event"  # event | detection | graph | walkback
    description: str = ""
    mitre_techniques: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Formatted string representation e.g. 'host:artifact'."""
        if ":" in self.artifact:
            return self.artifact
        return f"{self.host}:{self.artifact}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.timestamp:
            d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class KillChainPhase:
    """Findings and vector attribution for one of the 5 MITRE kill-chain phases."""

    name: str  # Initial Access | Execution | Credential Access | Discovery | Lateral Movement
    status: str = "unconfirmed"  # confirmed | likely | suspected | unconfirmed
    vector: str = "unknown"
    confidence: float = 0.0
    entry_host: str | None = None
    entry_entity: str | None = None
    entry_time: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEntry:
    """A collapsed, scored forensic timeline item representing an activity."""

    timestamp: str
    host: str
    event_type: str
    score: float
    description: str
    count: int = 1
    end_timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ForensicInvestigationPackage:
    """Complete container for deterministic forensic investigation results."""

    incident_id: str
    incident_host: str
    incident_time: str
    entities_investigated: int = 0
    events_analyzed: int = 0
    attack_chain: list[str] = field(default_factory=list)
    kill_chain_phases: dict[str, KillChainPhase] = field(default_factory=dict)
    timeline: list[TimelineEntry] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    top_findings: list[str] = field(default_factory=list)
    markdown_report: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_host": self.incident_host,
            "incident_time": self.incident_time,
            "entities_investigated": self.entities_investigated,
            "events_analyzed": self.events_analyzed,
            "attack_chain": self.attack_chain,
            "kill_chain_phases": {
                k: v.to_dict() for k, v in self.kill_chain_phases.items()
            },
            "timeline": [t.to_dict() for t in self.timeline],
            "mitre_techniques": self.mitre_techniques,
            "top_findings": self.top_findings,
            "markdown_report": self.markdown_report,
        }
