"""Complexity gate: decide whether a case warrants the swarm.

Single-agent investigation is cheaper and fine for most alerts. The swarm only
fires above a complexity threshold — enough distinct entities, a broad enough
technique spread, or a broad enough *tactic* spread (multiple distinct kill-chain
stages, e.g. Initial Access + Impact) that competing explanations are plausible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.tools.mitre import lookup_technique

# Defaults; overridable per tenant via a flag in the orchestrator.
DEFAULT_ENTITY_THRESHOLD = 3
DEFAULT_TECHNIQUE_THRESHOLD = 3
# Two or more distinct MITRE tactics (kill-chain stages) already signals a
# multi-stage attack even when the raw technique count is low.
DEFAULT_TACTIC_THRESHOLD = 2


@dataclass(frozen=True)
class ComplexityAssessment:
    is_complex: bool
    entity_count: int
    technique_count: int
    tactic_count: int = 0
    reasons: list[str] = field(default_factory=list)


def _count_entities(signal: dict) -> int:
    keys = ("src_ip", "dst_ip", "domain", "file_hash", "url", "hostname", "username")
    iocs = signal.get("iocs", {}) if isinstance(signal.get("iocs"), dict) else {}
    distinct = {signal.get(k) for k in keys if signal.get(k)} | {iocs.get(k) for k in keys if iocs.get(k)}
    distinct.discard(None)
    # Also count explicitly-listed related entities.
    related = signal.get("related_entities") or []
    return len(distinct) + (len(related) if isinstance(related, list) else 0)


def _count_tactics(technique_ids: list[str]) -> int:
    """Count distinct MITRE tactics spanned by the given technique IDs.

    Sub-technique IDs (e.g. ``T1021.002``) are normalised to their parent
    technique (``T1021``) before lookup. Unrecognised technique IDs (outside
    the lightweight reference in ``app.tools.mitre``) contribute nothing —
    this is a best-effort heuristic signal, not an exhaustive ATT&CK mapping.
    """
    tactics: set[str] = set()
    for technique_id in technique_ids:
        base_id = str(technique_id).split(".")[0].upper()
        info = lookup_technique(base_id)
        tactic_id = info.get("tactic_id")
        if tactic_id and tactic_id != "Unknown":
            tactics.add(tactic_id)
    return len(tactics)


def assess_complexity(
    signal: dict,
    *,
    entity_threshold: int = DEFAULT_ENTITY_THRESHOLD,
    technique_threshold: int = DEFAULT_TECHNIQUE_THRESHOLD,
    tactic_threshold: int = DEFAULT_TACTIC_THRESHOLD,
) -> ComplexityAssessment:
    """Assess whether ``signal`` (an alert-like dict) is complex enough to swarm."""
    entities = _count_entities(signal)
    technique_ids = signal.get("techniques") or signal.get("mitre_techniques") or []
    techniques = len(technique_ids)
    tactics = _count_tactics(technique_ids)
    reasons: list[str] = []
    if entities >= entity_threshold:
        reasons.append(f"{entities} distinct entities (>= {entity_threshold})")
    if techniques >= technique_threshold:
        reasons.append(f"{techniques} MITRE techniques (>= {technique_threshold})")
    if tactics >= tactic_threshold:
        reasons.append(f"{tactics} distinct MITRE tactics (>= {tactic_threshold})")
    return ComplexityAssessment(
        is_complex=bool(reasons),
        entity_count=entities,
        technique_count=techniques,
        tactic_count=tactics,
        reasons=reasons,
    )
