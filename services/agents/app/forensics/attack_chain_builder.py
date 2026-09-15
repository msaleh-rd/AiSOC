"""Build causal attack chains from evidence stages and cross-host bridges.

Ported from sxsecurityinvestigator/investigator/reporting/attack_chain_builder.py
for AiSOC. Links parent-child processes, script executions, and cross-host network
pivots into a concise, ordered attack narrative.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.forensics.models import AttackStage

_SCRIPT_EXTENSIONS = (".ps1", ".py", ".sh", ".bat", ".vbs", ".js", ".hta", ".psm1")


class AttackChainBuilder:
    """Builds a linear, causal attack chain from ranked AttackStage objects and host bridges."""

    def __init__(self, max_chain_stages: int = 10):
        self.max_chain_stages = max_chain_stages

    def build(
        self,
        stages: list[AttackStage],
        seed_host: str | None = None,
        bridges: list[tuple[str, str, str]] | None = None,
    ) -> list[str]:
        """Build ordered attack chain from stages and host bridges.

        Args:
            stages: Evidence-based attack stages.
            seed_host: Initial anchor host (e.g. entry host or victim).
            bridges: Optional list of (src_host, dst_host, bridge_label) discovered in netflow/auth.
        """
        if not stages:
            return [seed_host] if seed_host else []

        ordered = self._order_stages(stages, seed_host)
        chain: list[str] = []
        prev_host: str | None = None

        bridge_map: dict[tuple[str, str], str] = {}
        if bridges:
            for src, dst, label in bridges:
                bridge_map[(src.lower(), dst.lower())] = label

        for stage in ordered:
            curr_host = stage.host.lower()
            if prev_host and curr_host != prev_host:
                # Insert bridge between different hosts
                bridge = bridge_map.get((prev_host, curr_host))
                if not bridge:
                    bridge = f"{prev_host} -> {curr_host}"
                if bridge not in chain:
                    chain.append(bridge)

            label = stage.label.strip().strip('"').strip("'").strip("`")
            if label not in chain:
                chain.append(label)
            prev_host = curr_host

        if len(chain) > self.max_chain_stages:
            chain = self._cap_chain(chain, ordered, self.max_chain_stages)

        return chain

    def _order_stages(
        self,
        stages: list[AttackStage],
        seed_host: str | None,
    ) -> list[AttackStage]:
        def sort_key(s: AttackStage) -> tuple:
            ts = s.timestamp if s.timestamp else datetime.max
            seed_bonus = -1 if (seed_host and s.host.lower() == seed_host.lower()) else 0
            return (ts, seed_bonus, -s.score)

        return sorted(stages, key=sort_key)

    def _cap_chain(
        self,
        chain: list[str],
        stages: list[AttackStage],
        limit: int,
    ) -> list[str]:
        """Preserve the beginning (entry), the end (impact), and highest-scored stages."""
        if len(chain) <= limit:
            return chain

        # Always preserve first and last elements
        first = chain[0]
        last = chain[-1]
        middle = chain[1:-1]

        # Prioritize middle stages by highest score
        stage_scores: dict[str, float] = {}
        for s in stages:
            stage_scores[s.label] = max(stage_scores.get(s.label, 0.0), s.score)

        scored_middle = sorted(
            middle,
            key=lambda item: stage_scores.get(item, 10.0 if "->" in item else 0.0),
            reverse=True,
        )

        keep_count = limit - 2
        kept_set = set(scored_middle[:keep_count])
        kept_set.add(first)
        kept_set.add(last)

        # Retain original narrative order
        return [c for c in chain if c in kept_set]
