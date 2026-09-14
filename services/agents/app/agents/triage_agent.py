"""
Triage Agent: first responder that classifies severity, extracts IOCs,
maps MITRE techniques, and decides whether automated response is safe.
"""

from __future__ import annotations

import ipaddress
import json
import re

import structlog

from app.confidence import score_triage
from app.memory.distillation import build_signature_for_state, compounding_memory
from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.tools.mitre import map_techniques_to_kill_chain

logger = structlog.get_logger()

_CRITICAL_KEYWORDS = {
    "ransomware",
    "lateral movement",
    "credential dump",
    "domain admin",
    "exfiltration",
    "mimikatz",
    "cobalt strike",
    "c2",
    "beacon",
    "rootkit",
    "supply chain",
    "zero-day",
    "data breach",
}

_HIGH_KEYWORDS = {
    "phishing",
    "malware",
    "exploit",
    "privilege escalation",
    "brute force",
    "suspicious login",
    "anomaly",
    "backdoor",
}


def _score_alert(state: InvestigationState) -> tuple[str, float]:
    """Return (severity, risk_score) based on alert content heuristics."""
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    risk = state.raw_alert.get("risk_score", 0.0)

    if any(kw in text for kw in _CRITICAL_KEYWORDS):
        return "critical", max(risk, 0.9)
    if any(kw in text for kw in _HIGH_KEYWORDS):
        return "high", max(risk, 0.7)
    return "medium", max(risk, 0.4)


# ─── Regex IOC mining over the full alert text ───────────────────────────────
#
# Vendor alerts (Wazuh, Suricata, Zeek…) bury IPs/URLs/hashes deep inside
# raw_event JSON, not in the 5 flat fields the structured extractor reads.
# Mirror the reference triage skill-chain's ioc-extractor: regex-mine the
# complete serialized alert so nested indicators surface too.

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
# Conservative TLD allow-list keeps JSON keys / file paths from matching.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|ru|cn|info|biz|top|cc|onion)\b",
    re.IGNORECASE,
)

_BORING_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}  # noqa: S104


def _valid_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return value not in _BORING_IPS and not ip.is_loopback and not ip.is_multicast


def _extract_iocs_from_text(text: str, *, cap: int = 25) -> list[dict]:
    """Regex-mine IPs, URLs, hashes and domains from arbitrary alert text."""
    iocs: list[dict] = []
    seen: set[str] = set()

    def _add(value: str, ioc_type: str) -> None:
        v = value.strip().rstrip(".,;)")
        if v and v.lower() not in seen:
            seen.add(v.lower())
            iocs.append({"value": v, "ioc_type": ioc_type})

    for m in _IPV4_RE.findall(text):
        if _valid_public_ip(m):
            _add(m, "ip")
    for m in _URL_RE.findall(text):
        _add(m, "url")
    for m in _HASH_RE.findall(text):
        _add(m, "hash")
    for m in _DOMAIN_RE.findall(text):
        _add(m, "domain")
    return iocs[:cap]


async def run_triage(state: InvestigationState) -> InvestigationState:
    """
    Execute the triage phase:
    - Score alert severity
    - Extract IOCs from raw alert
    - Map MITRE techniques
    - Propose initial actions
    """
    logger.info("Triage agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    # --- Severity scoring ---
    severity, risk_score = _score_alert(state)
    state.add_finding(f"Triage severity: {severity} (risk_score={risk_score:.2f})")

    # --- IOC extraction from raw alert ---
    iocs: list[dict] = []
    raw = state.raw_alert
    if raw.get("src_ip"):
        iocs.append({"value": raw["src_ip"], "ioc_type": "ip"})
    if raw.get("dst_ip"):
        iocs.append({"value": raw["dst_ip"], "ioc_type": "ip"})
    if raw.get("domain"):
        iocs.append({"value": raw["domain"], "ioc_type": "domain"})
    if raw.get("file_hash"):
        iocs.append({"value": raw["file_hash"], "ioc_type": "hash"})
    if raw.get("url"):
        iocs.append({"value": raw["url"], "ioc_type": "url"})

    # Regex-mine the FULL serialized alert (summary + nested raw_event JSON)
    # so indicators buried in vendor payloads surface as well.
    try:
        full_text = state.alert_summary + " " + json.dumps(raw, default=str)
    except (TypeError, ValueError):
        full_text = state.alert_summary + " " + str(raw)
    known = {str(i["value"]).lower() for i in iocs}
    for ioc in _extract_iocs_from_text(full_text):
        if str(ioc["value"]).lower() not in known:
            known.add(str(ioc["value"]).lower())
            iocs.append(ioc)

    state.add_finding(f"Extracted {len(iocs)} IOCs for enrichment: {[i['value'] for i in iocs]}")
    state.threat_intel["pending_iocs"] = iocs

    # --- Promote host/IP/user identities onto the entity blackboard so the
    # supervisor and the platform-evidence collector have concrete targets.
    existing_entities = {
        str(e.get("value", "")).lower() for e in state.entities if isinstance(e, dict)
    }

    def _promote(value: str | None, entity_type: str) -> None:
        if value and str(value).lower() not in existing_entities:
            existing_entities.add(str(value).lower())
            state.entities.append({"entity_type": entity_type, "value": str(value)})

    _promote(raw.get("hostname"), "host")
    device = raw.get("device")
    if isinstance(device, dict):
        _promote(device.get("name"), "host")
    for h in raw.get("affected_hosts") or []:
        _promote(h, "host")
    for u in raw.get("affected_users") or []:
        _promote(u, "user")
    _promote(raw.get("src_ip"), "ip")
    _promote(raw.get("dst_ip"), "ip")
    for ioc in iocs:
        if ioc["ioc_type"] == "ip":
            _promote(ioc["value"], "ip")

    # --- MITRE mapping ---
    techniques = raw.get("mitre_techniques", [])
    if techniques:
        kill_chain = map_techniques_to_kill_chain(techniques)
        state.mitre_mappings = techniques
        state.add_finding(f"MITRE kill chain: {kill_chain}")

    # --- Propose isolation if critical ---
    if severity == "critical" and raw.get("hostname"):
        state.proposed_actions.append(
            ProposedAction(
                action_type="isolate_host",
                description=f"Isolate host '{raw['hostname']}' from network",
                risk_level=ActionRisk.HIGH,
                target=raw["hostname"],
                requires_approval=True,
                rationale="Critical severity alert with host identifier present",
            )
        )

    confidence, basis, verdict = score_triage(state)

    # --- Compounding memory: nudge confidence using historical verdict priors
    # for this alert signature (closes the loop between record_outcome's
    # write path and live triage — see app.memory.distillation). Best-effort;
    # never let a memory lookup failure break triage.
    try:
        signature = build_signature_for_state(state, classification=severity)
        await compounding_memory.ensure_fresh(str(state.tenant_id))
        adjustment = compounding_memory.get_memory_verdict_adjustment(
            signature, tenant_id=str(state.tenant_id)
        )
        if adjustment:
            confidence = max(0.0, min(1.0, confidence + adjustment))
            basis = [*basis, f"Compounding memory: {adjustment:+.2f} for signature '{signature}'"]
    except Exception as exc:  # noqa: BLE001 — memory lookup is best-effort
        logger.debug("triage.compounding_memory_lookup_failed", error=str(exc)[:200])

    # Never let this deterministic keyword heuristic CLOBBER a
    # higher-confidence verdict already on the state (e.g. the LLM
    # auto-triage stage, which reasons over the full alert). The heuristic
    # only fills in when it's the best signal available.
    if state.verdict and state.confidence > confidence:
        state.add_finding(
            f"Triage heuristic ({verdict}, confidence={confidence:.2f}) kept the "
            f"stronger upstream verdict: {state.verdict} (confidence={state.confidence:.2f})"
        )
    else:
        state.confidence = confidence
        state.confidence_basis = basis
        state.verdict = verdict
        state.add_finding(f"Triage verdict: {verdict} (confidence={confidence:.2f})")

    state.add_finding("Triage phase complete — proceeding to enrichment")
    logger.info(
        "Triage complete",
        severity=severity,
        ioc_count=len(iocs),
        confidence=round(confidence, 2),
        verdict=verdict,
    )
    return state
