"""Deterministic Markdown investigation report generator (Zero-LLM Mode).

Ported from sxsecurityinvestigator/investigator/llm/report_generator.py for AiSOC.
Renders complete, structured Markdown investigation reports containing 5-phase MITRE
breakdown, attack chains, and noise-collapsed timelines without requiring an LLM.
"""

from __future__ import annotations

from typing import Any

from app.forensics.models import (
    ForensicInvestigationPackage,
    KillChainPhase,
    TimelineEntry,
)


class DeterministicReportGenerator:
    """Renders complete, publication-ready Markdown incident reports offline."""

    def generate(self, package: ForensicInvestigationPackage) -> str:
        lines: list[str] = [
            "# Investigation Report",
            "",
            f"**Incident:** {package.incident_host} @ {package.incident_time}",
            f"**Entities Investigated:** {package.entities_investigated}",
            f"**Events Analyzed:** {package.events_analyzed:,}",
            "",
            "---",
            "",
        ]

        # 1. Five MITRE Kill-Chain Phases
        phase_order = [
            ("initial_access", "Initial Access (MITRE Phase 1)"),
            ("execution", "Execution (MITRE Phase 2)"),
            ("credential_access", "Credential Access (MITRE Phase 3)"),
            ("discovery", "Discovery (MITRE Phase 4)"),
            ("lateral_movement", "Lateral Movement (MITRE Phase 5)"),
        ]

        for phase_key, title in phase_order:
            phase = package.kill_chain_phases.get(phase_key)
            lines.append(f"## {title}")
            if not phase or phase.status == "unconfirmed":
                lines.append("**Status:** unconfirmed | **Confidence:** 0.00")
                lines.append("- No confirmed activity observed for this phase.")
                lines.append("")
                continue

            techniques_str = ", ".join(phase.mitre_techniques) or "None"
            lines.append(
                f"**Status:** {phase.status} | **Vector:** {phase.vector} | **Confidence:** {phase.confidence:.2f}"
            )
            if phase.entry_host:
                lines.append(f"**Entry host:** {phase.entry_host}")
            if phase.entry_entity:
                lines.append(f"**Entry entity:** `{phase.entry_entity}`")
            lines.append(f"**MITRE techniques:** {techniques_str}")
            lines.append("")

            for finding in phase.findings:
                lines.append(f"- {finding}")

            if phase.candidates:
                lines.append("")
                lines.append("### Top Candidates")
                for c in phase.candidates:
                    lines.append(f"- `{c.get('entity')}` (score={c.get('score', 0):.2f}, vector={c.get('vector', 'unknown')})")

            lines.append("")

        # 2. Reconstructed Attack Chain
        lines.append("## Attack Chain")
        lines.append("")
        if package.attack_chain:
            chain_str = " → ".join(f"`{stage}`" for stage in package.attack_chain)
            lines.append(chain_str)
        else:
            lines.append(f"`{package.incident_host}:activity`")
        lines.append("")

        # 3. Top Technical Findings
        if package.top_findings:
            lines.append("## Technical Findings")
            lines.append("")
            for f in package.top_findings:
                lines.append(f"- {f}")
            lines.append("")

        # 4. Collapsed Forensic Timeline
        lines.append("## Forensic Timeline")
        lines.append("")
        if package.timeline:
            lines.append("| Timestamp | Host | Event Type | Score | Description |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for t in package.timeline:
                clean_desc = t.description.replace("|", "/")
                lines.append(f"| {t.timestamp} | {t.host} | {t.event_type} | {t.score:.1f} | {clean_desc} |")
        else:
            lines.append("- No timeline entries recorded.")
        lines.append("")

        return "\n".join(lines)
