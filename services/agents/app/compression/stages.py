"""Individual stage implementations for the 7-stage compression pipeline.

Each stage is a callable class that takes a list of ``CorrelatedEvent`` and
returns a filtered/transformed list.  Stages are pure functions of their
input — no IO, no LLM calls — so they are fully unit-testable and
deterministic.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from app.compression.models import CorrelatedEvent, MitreTechnique


# ---------------------------------------------------------------------------
# Stage 1: Temporal Filter
# ---------------------------------------------------------------------------


class TemporalFilter:
    """Cluster events within a time window around the incident.

    Events outside the window are discarded.  Events within the window are
    kept and tagged with a temporal cluster ID for downstream stages.
    """

    def __init__(self, window_before_minutes: int = 60, window_after_minutes: int = 30) -> None:
        self._before = timedelta(minutes=window_before_minutes)
        self._after = timedelta(minutes=window_after_minutes)

    def filter_events(
        self,
        events: list[CorrelatedEvent],
        incident_time: datetime | None = None,
    ) -> tuple[list[CorrelatedEvent], float]:
        """Return (filtered_events, reduction_ratio)."""
        if not events:
            return [], 0.0

        if incident_time is None:
            # Use the median timestamp as the incident anchor.
            sorted_ts = sorted(e.timestamp for e in events)
            incident_time = sorted_ts[len(sorted_ts) // 2]

        start = incident_time - self._before
        end = incident_time + self._after

        filtered = [e for e in events if start <= e.timestamp <= end]
        if not filtered:
            # Safety net: never discard everything.
            filtered = events

        reduction = 1.0 - (len(filtered) / max(len(events), 1))
        return filtered, reduction


# ---------------------------------------------------------------------------
# Stage 2: Entity Correlator
# ---------------------------------------------------------------------------


class EntityCorrelator:
    """Group events by shared entities (IP, user, host).

    Within each entity group, keep the highest-risk representative and
    roll up the rest as ``raw_events``.
    """

    def correlate_events(
        self, events: list[CorrelatedEvent]
    ) -> tuple[list[CorrelatedEvent], float]:
        if not events:
            return [], 0.0

        groups: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        for e in events:
            groups[e.entity_id].append(e)

        correlated: list[CorrelatedEvent] = []
        for entity_id, group in groups.items():
            # Keep the highest-risk event as the representative.
            group.sort(key=lambda e: e.risk_score, reverse=True)
            representative = group[0]
            # Attach subordinate events as raw_events on the representative.
            if len(group) > 1:
                representative.raw_events = [e.to_dict() for e in group[1:]]
            correlated.append(representative)

        reduction = 1.0 - (len(correlated) / max(len(events), 1))
        return correlated, reduction


# ---------------------------------------------------------------------------
# Stage 3: Behavioral Filter
# ---------------------------------------------------------------------------


class BehavioralFilter:
    """Keep only events that are behaviorally anomalous.

    An event is considered anomalous if its risk score exceeds the
    ``anomaly_threshold``.  This is a simplified version — a production
    system would compare against a per-entity baseline.
    """

    def __init__(self, anomaly_threshold: float = 0.3) -> None:
        self._threshold = anomaly_threshold

    def filter_anomalies(
        self, events: list[CorrelatedEvent]
    ) -> tuple[list[CorrelatedEvent], float]:
        if not events:
            return [], 0.0

        anomalous = [e for e in events if e.risk_score >= self._threshold]
        if not anomalous:
            # Safety net: keep top 50% by risk score.
            events.sort(key=lambda e: e.risk_score, reverse=True)
            anomalous = events[: max(1, len(events) // 2)]

        reduction = 1.0 - (len(anomalous) / max(len(events), 1))
        return anomalous, reduction


# ---------------------------------------------------------------------------
# Stage 4: Deduplicator
# ---------------------------------------------------------------------------


class EventDeduplicator:
    """Collapse near-identical events based on (entity, action, event_type)."""

    def deduplicate(
        self, events: list[CorrelatedEvent]
    ) -> tuple[list[CorrelatedEvent], float]:
        if not events:
            return [], 0.0

        seen: dict[str, CorrelatedEvent] = {}
        for e in events:
            key = f"{e.entity_id}|{e.action}|{e.event_type}"
            if key not in seen or e.risk_score > seen[key].risk_score:
                seen[key] = e

        deduped = list(seen.values())
        reduction = 1.0 - (len(deduped) / max(len(events), 1))
        return deduped, reduction


# ---------------------------------------------------------------------------
# Stage 5: Graph Analyzer
# ---------------------------------------------------------------------------


class GraphAnalyzer:
    """Detect attack patterns from entity relationships.

    Builds an in-memory entity graph and identifies common attack patterns:
    lateral movement chains, privilege escalation sequences, and
    exfiltration paths.
    """

    # Common attack pattern detectors.
    _LATERAL_KEYWORDS = {"smb", "rdp", "ssh", "psexec", "wmi", "lateral", "remote"}
    _PRIVESC_KEYWORDS = {"privilege", "escalation", "sudo", "admin", "root", "uac"}
    _EXFIL_KEYWORDS = {"exfil", "upload", "transfer", "dns tunnel", "c2", "beacon"}

    def analyze_relationships(
        self, events: list[CorrelatedEvent]
    ) -> tuple[list[dict[str, Any]], float]:
        """Return (detected_patterns, reduction_ratio).

        ``reduction_ratio`` here represents the fraction of events that
        are NOT tied to any detected pattern.
        """
        if not events:
            return [], 0.0

        patterns: list[dict[str, Any]] = []
        pattern_entities: set[str] = set()

        for e in events:
            action_lower = e.action.lower()
            event_type_lower = e.event_type.lower()
            combined = f"{action_lower} {event_type_lower}"

            if any(kw in combined for kw in self._LATERAL_KEYWORDS):
                patterns.append({"type": "lateral_movement", "entity": e.entity_id, "action": e.action})
                pattern_entities.add(e.entity_id)
            elif any(kw in combined for kw in self._PRIVESC_KEYWORDS):
                patterns.append({"type": "privilege_escalation", "entity": e.entity_id, "action": e.action})
                pattern_entities.add(e.entity_id)
            elif any(kw in combined for kw in self._EXFIL_KEYWORDS):
                patterns.append({"type": "exfiltration", "entity": e.entity_id, "action": e.action})
                pattern_entities.add(e.entity_id)

        non_pattern = len([e for e in events if e.entity_id not in pattern_entities])
        reduction = non_pattern / max(len(events), 1)
        return patterns, reduction


# ---------------------------------------------------------------------------
# Stage 6: Risk Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Re-score events using pattern context + base risk.

    Events tied to detected attack patterns get a pattern bonus.  Events
    are sorted by final risk and only the top-N are kept.
    """

    def __init__(self, max_output: int = 20, pattern_bonus: float = 0.2) -> None:
        self._max_output = max_output
        self._pattern_bonus = pattern_bonus

    def score_risks(
        self,
        events: list[CorrelatedEvent],
        patterns: list[dict[str, Any]],
    ) -> list[CorrelatedEvent]:
        if not events:
            return []

        pattern_entities = {p.get("entity") for p in patterns if p.get("entity")}

        for e in events:
            if e.entity_id in pattern_entities:
                e.risk_score = min(1.0, e.risk_score + self._pattern_bonus)

        events.sort(key=lambda e: e.risk_score, reverse=True)
        return events[: self._max_output]


# ---------------------------------------------------------------------------
# Stage 7: Abstraction Engine
# ---------------------------------------------------------------------------


class AbstractionEngine:
    """Summarise events into entity-level groups.

    Each entity gets a single representative event whose action is a
    summary of all actions for that entity, and whose risk_score is the
    maximum within the group.
    """

    def abstract_events(self, events: list[CorrelatedEvent]) -> list[CorrelatedEvent]:
        if not events:
            return []

        groups: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        for e in events:
            groups[e.entity_id].append(e)

        abstractions: list[CorrelatedEvent] = []
        for entity_id, group in groups.items():
            group.sort(key=lambda e: e.risk_score, reverse=True)
            representative = group[0]
            if len(group) > 1:
                actions = list(dict.fromkeys(e.action for e in group))  # dedup preserving order
                representative.action = " → ".join(actions[:5])
                if len(actions) > 5:
                    representative.action += f" (+{len(actions) - 5} more)"
                representative.raw_events = [e.to_dict() for e in group[1:]]
                representative.risk_score = max(e.risk_score for e in group)
            abstractions.append(representative)

        abstractions.sort(key=lambda e: e.risk_score, reverse=True)
        return abstractions


# ---------------------------------------------------------------------------
# Event normaliser — convert raw dicts to CorrelatedEvent
# ---------------------------------------------------------------------------


def normalise_event(raw: dict[str, Any]) -> CorrelatedEvent:
    """Convert a raw alert/event dict into a ``CorrelatedEvent``.

    Handles both OCSF-format events and AiSOC's ``RawAlert`` format.
    """
    ts_raw = raw.get("timestamp") or raw.get("created_at") or raw.get("time")
    if isinstance(ts_raw, datetime):
        ts = ts_raw
    elif isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    entity = (
        raw.get("entity_id")
        or raw.get("entity")
        or raw.get("src_ip")
        or raw.get("hostname")
        or raw.get("username")
        or raw.get("actor", {}).get("user", {}).get("name", "")
        or "unknown"
    )

    action = raw.get("action") or raw.get("activity_name") or raw.get("title") or "unknown"
    event_type = raw.get("event_type") or raw.get("type_name") or raw.get("category_name") or "unknown"
    risk_score = float(raw.get("risk_score", raw.get("severity_id", 0)) or 0)
    confidence = float(raw.get("confidence", 0.5) or 0.5)

    mitre = None
    technique_id = raw.get("mitre_technique_id") or raw.get("technique_id")
    if technique_id:
        mitre = MitreTechnique(
            technique_id=str(technique_id),
            technique_name=raw.get("mitre_technique_name", ""),
            tactic_name=raw.get("mitre_tactic", ""),
        )

    return CorrelatedEvent(
        timestamp=ts,
        entity_id=str(entity),
        event_type=str(event_type),
        action=str(action),
        risk_score=min(1.0, max(0.0, risk_score)),
        confidence=min(1.0, max(0.0, confidence)),
        mitre_technique=mitre,
    )
