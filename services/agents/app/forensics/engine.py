"""Unified Forensics Engine orchestrating timeline collapsing, kill-chain analysis, and attack-chain sequencing.

AiSOC Dual-Track Investigation Core. Runs unconditionally in <100ms with zero LLM tokens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.forensics.attack_chain_builder import AttackChainBuilder
from app.forensics.deterministic_report import DeterministicReportGenerator
from app.forensics.kill_chain_collector import KillChainCollector
from app.forensics.models import (
    AttackStage,
    ForensicInvestigationPackage,
    KillChainPhase,
    TimelineEntry,
)
from app.forensics.timeline_collapser import TimelineCollapser


class ForensicsEngine:
    """High-throughput deterministic forensic engine for dual-track investigation."""

    def __init__(
        self,
        max_timeline_entries: int = 50,
        max_chain_stages: int = 10,
    ):
        self.collapser = TimelineCollapser(max_entries=max_timeline_entries)
        self.collector = KillChainCollector()
        self.chain_builder = AttackChainBuilder(max_chain_stages=max_chain_stages)
        self.report_generator = DeterministicReportGenerator()

    def analyze(
        self,
        events: list[dict[str, Any]],
        incident_id: str = "unknown",
        incident_host: str | None = None,
        incident_time: str | None = None,
        entities: list[dict[str, Any]] | None = None,
        raw_alert: dict[str, Any] | None = None,
    ) -> ForensicInvestigationPackage:
        """Run deterministic forensic analysis over all gathered events and entities."""
        # Determine anchor host and time
        host = (
            incident_host
            or (raw_alert.get("hostname") if raw_alert else None)
            or (raw_alert.get("affected_hosts", [None])[0] if raw_alert and raw_alert.get("affected_hosts") else None)
            or "unknown_host"
        )
        time_str = (
            incident_time
            or (raw_alert.get("timestamp") if raw_alert else None)
            or (raw_alert.get("time") if raw_alert else None)
            or datetime.now(timezone.utc).isoformat()
        )

        all_items: list[dict[str, Any]] = []
        if raw_alert:
            all_items.append(raw_alert)
        if events:
            all_items.extend(events)
        if entities:
            all_items.extend(entities)

        # 1. 5-Phase MITRE Kill-Chain Collection & Attack Stages
        phases, stages = self.collector.collect(all_items, seed_host=host)

        # 2. Attack Chain Sequencing
        chain = self.chain_builder.build(stages, seed_host=host)

        # 3. Timeline Noise Collapsing & Burst Suppression
        timeline = self.collapser.build_timeline(all_items)

        # 4. Extract Top Findings & MITRE Techniques
        all_techniques: set[str] = set()
        top_findings: list[str] = []
        for phase in phases.values():
            all_techniques.update(phase.mitre_techniques)
            if phase.findings:
                top_findings.extend(phase.findings)

        # 5. Build Package
        entities_count = len(entities) if entities else (1 if host != "unknown_host" else 0)
        package = ForensicInvestigationPackage(
            incident_id=incident_id,
            incident_host=host,
            incident_time=time_str,
            entities_investigated=entities_count,
            events_analyzed=len(all_items),
            attack_chain=chain,
            kill_chain_phases=phases,
            timeline=timeline,
            mitre_techniques=sorted(list(all_techniques)),
            top_findings=top_findings[:10],
        )

        # 6. Render Deterministic Markdown Report
        package.markdown_report = self.report_generator.generate(package)
        return package
