"""PageRank-based Root Cause Analysis engine.

Uses the causal graph built by ``CausalGraphBuilder`` to score entities as
potential root causes.  The scoring algorithm combines:

  1. **PageRank centrality** — entities with high causal influence score higher.
  2. **Topology position** — upstream dependencies are boosted over the target.
  3. **Temporal ordering** — entities whose anomalies precede the target's are
     boosted.
  4. **Criticality** — entities with more dependents (graph out-degree, i.e.
     entities they causally affect downstream) are weighted as more critical.
  5. **Risk score** — base risk from the compression pipeline.

The output is a ``RootCauseAnalysis`` dataclass with the identified root cause,
confidence score, supporting/contradicting evidence, and blast radius.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None  # type: ignore[assignment]

from app.compression.models import CorrelatedEvent
from app.rca.config import CausalFactors, load_causal_factors

logger = structlog.get_logger()


@dataclass
class RootCauseAnalysis:
    """Result of root cause analysis."""

    root_cause_entity: str
    target_entity: str
    confidence: float
    confidence_level: str  # "very_high" | "high" | "medium" | "low" | "very_low"
    attack_type: str
    supporting_evidence: list[dict[str, Any]]
    contradicting_evidence: list[dict[str, Any]]
    temporal_sequence: list[dict[str, Any]]
    attack_graph: dict[str, list[str]]
    estimated_blast_radius: int
    remediation_complexity: str  # "simple" | "moderate" | "complex"
    pagerank_scores: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause_entity": self.root_cause_entity,
            "target_entity": self.target_entity,
            "confidence": round(self.confidence, 4),
            "confidence_level": self.confidence_level,
            "attack_type": self.attack_type,
            "supporting_evidence_count": len(self.supporting_evidence),
            "contradicting_evidence_count": len(self.contradicting_evidence),
            "temporal_sequence": self.temporal_sequence[:10],
            "attack_graph": self.attack_graph,
            "estimated_blast_radius": self.estimated_blast_radius,
            "remediation_complexity": self.remediation_complexity,
            "pagerank_scores": {k: round(v, 6) for k, v in self.pagerank_scores.items()},
        }


class PageRankRCA:
    """Root Cause Analysis engine using PageRank on the causal graph."""

    def __init__(self, config: CausalFactors | None = None) -> None:
        if nx is None:
            raise ImportError("networkx is required for PageRank RCA")
        self.config = config or load_causal_factors()

    def analyze(
        self,
        graph: nx.DiGraph,
        target_entity: str,
        events: list[CorrelatedEvent],
    ) -> RootCauseAnalysis:
        """Run PageRank RCA on the causal graph.

        Args:
            graph: Causal graph built by ``CausalGraphBuilder``.
            target_entity: The entity experiencing the observed issue.
            events: Compressed events for evidence gathering.

        Returns:
            ``RootCauseAnalysis`` with identified root cause and supporting data.
        """
        if graph.number_of_nodes() == 0:
            return self._empty_result(target_entity)

        # Step 1: Compute PageRank centrality on the causal graph.
        if graph.number_of_nodes() == 1:
            pagerank = {next(iter(graph.nodes)): 1.0}
        else:
            try:
                pagerank = nx.pagerank(graph, alpha=0.85, max_iter=100, weight="weight")
            except (nx.PowerIterationFailedConvergence, nx.NetworkXError, nx.AmbiguousSolution):
                # Fall back to a uniform distribution if PageRank fails to
                # converge (e.g. degenerate graph topology).
                pagerank = {node: 1.0 / max(graph.number_of_nodes(), 1) for node in graph.nodes}

        # Step 2: Score each entity as a potential root cause.
        scored = self._score_candidates(graph, target_entity, events, pagerank)

        if not scored:
            return self._empty_result(target_entity)

        # Step 3: Identify the winner.
        scored.sort(key=lambda x: x[1], reverse=True)
        root_cause_entity, root_cause_score, root_cause_reason = scored[0]

        # Step 4: Gather evidence.
        supporting = self._gather_supporting_evidence(events, root_cause_entity)
        contradicting = self._gather_contradicting_evidence(events, root_cause_entity)
        temporal_seq = self._build_temporal_sequence(events, root_cause_entity)

        # Step 5: Compute blast radius.
        try:
            blast_radius = len(nx.descendants(graph, root_cause_entity))
        except nx.NetworkXError:
            blast_radius = 0

        # Step 6: Confidence calibration.
        confidence = self._calibrate_confidence(
            root_cause_score, scored, len(supporting), len(contradicting)
        )

        # Step 7: Attack type inference.
        attack_type = self._infer_attack_type(events, root_cause_entity)

        # Step 8: Remediation complexity.
        remediation = self._assess_remediation_complexity(blast_radius, len(events))

        # Step 9: Build attack graph from the scored results.
        attack_graph: dict[str, list[str]] = {}
        for entity, score, reason in scored[:10]:
            attack_graph.setdefault(reason, []).append(entity)

        return RootCauseAnalysis(
            root_cause_entity=root_cause_entity,
            target_entity=target_entity,
            confidence=confidence,
            confidence_level=self._confidence_level(confidence),
            attack_type=attack_type,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            temporal_sequence=temporal_seq,
            attack_graph=attack_graph,
            estimated_blast_radius=blast_radius,
            remediation_complexity=remediation,
            pagerank_scores={k: round(v, 6) for k, v in pagerank.items()},
        )

    def _score_candidates(
        self,
        graph: nx.DiGraph,
        target_entity: str,
        events: list[CorrelatedEvent],
        pagerank: dict[str, float],
    ) -> list[tuple[str, float, str]]:
        """Score each entity as a potential root cause."""
        cf = self.config
        target_first_ts = self._earliest_timestamp(events, target_entity)
        scored: list[tuple[str, float, str]] = []

        for entity in graph.nodes:
            pr_score = pagerank.get(entity, 0.0)
            node_data = graph.nodes[entity]
            risk_score = float(node_data.get("risk_score", 0.0))
            base_score = pr_score * 0.4 + risk_score * 0.6

            # Factor 1: Topology position.
            is_target = entity == target_entity
            if is_target:
                topology_factor = cf.target_service_penalty
            else:
                path_length = self._shortest_path_length(graph, entity, target_entity)
                if path_length == 1:
                    topology_factor = cf.direct_dependency_boost
                elif path_length == 2:
                    topology_factor = cf.transitive_dependency_boost
                elif path_length < 999:
                    topology_factor = cf.distant_dependency_factor
                else:
                    topology_factor = cf.not_in_path_factor

            # Factor 2: Temporal ordering.
            temporal_factor = 1.0
            entity_first_ts = self._earliest_timestamp(events, entity)
            if entity_first_ts and target_first_ts and entity_first_ts < target_first_ts:
                delta = (target_first_ts - entity_first_ts).total_seconds()
                if delta > cf.temporal_threshold_seconds:
                    temporal_factor = cf.temporal_early_boost
                else:
                    temporal_factor = cf.temporal_moderate_boost
            elif entity_first_ts and target_first_ts and entity_first_ts > target_first_ts:
                temporal_factor = cf.temporal_late_boost

            # Factor 3: Criticality (number of dependents). Edges point
            # cause -> effect, so an entity's dependents are its successors
            # (the entities it can causally affect), not its predecessors.
            dependents = list(graph.successors(entity))
            criticality = 1.0 + (len(dependents) * cf.criticality_multiplier)

            final_score = base_score * topology_factor * temporal_factor * criticality
            reason = self._determine_reason(entity, events)
            scored.append((entity, final_score, reason))

        return scored

    @staticmethod
    def _shortest_path_length(graph: nx.DiGraph, source: str, target: str) -> int:
        try:
            return nx.shortest_path_length(graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return 999

    @staticmethod
    def _earliest_timestamp(events: list[CorrelatedEvent], entity: str) -> datetime | None:
        entity_events = [e for e in events if e.entity_id == entity]
        if not entity_events:
            return None
        return min(e.timestamp for e in entity_events)

    @staticmethod
    def _gather_supporting_evidence(
        events: list[CorrelatedEvent], root_cause: str
    ) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "risk_score": e.risk_score,
            }
            for e in events
            if e.entity_id == root_cause and e.risk_score > 0.3
        ]

    @staticmethod
    def _gather_contradicting_evidence(
        events: list[CorrelatedEvent], root_cause: str
    ) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "reason": "Activity from different entity with higher risk",
            }
            for e in events
            if e.entity_id != root_cause and e.risk_score > 0.5
        ][:5]

    @staticmethod
    def _build_temporal_sequence(
        events: list[CorrelatedEvent], root_cause: str
    ) -> list[dict[str, Any]]:
        relevant = [e for e in events if e.entity_id == root_cause]
        relevant.sort(key=lambda e: e.timestamp)
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "event_type": e.event_type,
                "entity": e.entity_id,
                "risk_score": e.risk_score,
            }
            for e in relevant[:8]
        ]

    @staticmethod
    def _calibrate_confidence(
        winner_score: float,
        all_scored: list[tuple[str, float, str]],
        supporting_count: int,
        contradicting_count: int,
    ) -> float:
        """Calibrate confidence based on score margin, evidence quality."""
        if len(all_scored) < 2:
            base = min(0.9, winner_score)
        else:
            margin = winner_score - all_scored[1][1]
            base = min(0.95, 0.5 + margin * 2)

        # Evidence quality adjustment.
        evidence_factor = 1.0
        if supporting_count > 3:
            evidence_factor += 0.1
        if contradicting_count > 2:
            evidence_factor -= 0.15

        return max(0.05, min(0.95, base * evidence_factor))

    @staticmethod
    def _confidence_level(confidence: float) -> str:
        if confidence > 0.9:
            return "very_high"
        elif confidence > 0.7:
            return "high"
        elif confidence > 0.5:
            return "medium"
        elif confidence > 0.3:
            return "low"
        else:
            return "very_low"

    @staticmethod
    def _infer_attack_type(events: list[CorrelatedEvent], root_cause: str) -> str:
        """Infer the primary attack type from root cause events."""
        rc_events = [e for e in events if e.entity_id == root_cause]
        keywords_map = {
            "lateral_movement": {"smb", "rdp", "ssh", "psexec", "lateral"},
            "privilege_escalation": {"privilege", "escalation", "sudo", "admin"},
            "credential_theft": {"credential", "mimikatz", "hash", "kerberos", "password"},
            "data_exfiltration": {"exfil", "upload", "transfer", "download"},
            "malware_execution": {"malware", "ransomware", "execute", "payload"},
            "c2_communication": {"c2", "beacon", "callback", "command"},
        }
        for event in rc_events:
            action_lower = event.action.lower()
            for attack_type, keywords in keywords_map.items():
                if any(kw in action_lower for kw in keywords):
                    return attack_type
        return "unknown"

    @staticmethod
    def _assess_remediation_complexity(blast_radius: int, event_count: int) -> str:
        if blast_radius > 10 or event_count > 50:
            return "complex"
        elif blast_radius > 5 or event_count > 20:
            return "moderate"
        else:
            return "simple"

    @staticmethod
    def _determine_reason(entity: str, events: list[CorrelatedEvent]) -> str:
        entity_events = [e for e in events if e.entity_id == entity]
        if not entity_events:
            return "Anomaly detected"
        top = max(entity_events, key=lambda e: e.risk_score)
        return f"{top.action} (risk: {top.risk_score:.2f})"

    @staticmethod
    def _empty_result(target_entity: str) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            root_cause_entity=target_entity,
            target_entity=target_entity,
            confidence=0.0,
            confidence_level="very_low",
            attack_type="unknown",
            supporting_evidence=[],
            contradicting_evidence=[],
            temporal_sequence=[],
            attack_graph={},
            estimated_blast_radius=0,
            remediation_complexity="simple",
            pagerank_scores={},
        )
