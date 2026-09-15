"""Active kill-chain phase hunts with anchor chaining and parallel probes.

Ported from sxsecurityinvestigator's orchestration layer
(``phase_brain.PHASE_SPECS`` + the per-phase runners in ``initial_access.py``,
``execution.py``, ``credential_access.py``, ``discovery.py``,
``lateral_movement.py``).

Unlike :class:`app.forensics.kill_chain_collector.KillChainCollector` (a
passive single-pass pattern matcher), this module hunts each MITRE phase in
kill-chain order with **anchor chaining**: a confirmed Initial Access verdict
anchors the Execution hunt on the entry host/time, Execution anchors
Credential Access, and so on. Within a phase, the independent search/technique
probes run concurrently (``asyncio.gather``), and the whole hunt track is
designed to run in parallel with the swarm and RCA tracks.

Noise-tagged events (``noise: True`` — see :mod:`app.forensics.noise`) are
excluded from matching so compliance-scan text never manufactures verdicts.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Any

import structlog

from app.forensics.models import KillChainPhase

logger = structlog.get_logger()

PHASE_ORDER = (
    "initial_access",
    "execution",
    "credential_access",
    "discovery",
    "lateral_movement",
)

# Per-phase hunt specs — search terms + techniques ported from
# sxsecurityinvestigator phase_brain.PHASE_SPECS.
PHASE_SPECS: dict[str, dict[str, Any]] = {
    "initial_access": {
        "label": "Initial Access",
        "techniques": ("T1078", "T1110", "T1133", "T1190", "T1566", "T1189"),
        "searches": (
            "openvpn", "wireguard", "ngrok", "cloudflared", "vpn tunnel",
            "failed password", "invalid user", "authentication failure",
            "accepted password", "accepted publickey", "4625",
            "external logon", "rdp", "3389", "vnc", "sshd", "ssh accepted",
            "brute force", "password spray", "phishing",
        ),
        "technique_boost": 0.08,
    },
    "execution": {
        "label": "Execution",
        "techniques": ("T1059", "T1053", "T1204"),
        "searches": (
            "powershell -enc", "certutil", "scheduled task", "wmic process",
            "/bin/sh -c", "/bin/bash -c", "mshta", "wscript", "cscript",
            "cmd.exe /c", "base64 -d",
        ),
        "technique_boost": 0.08,
    },
    "credential_access": {
        "label": "Credential Access",
        "techniques": ("T1003", "T1110", "T1558", "T1212", "T1552"),
        "searches": (
            "mimikatz", "lsass", "procdump", "hydra", "kerberoast",
            "zerologon", "secretsdump", "reg save sam", "password spray",
            "/etc/shadow", "id_rsa", "authorized_keys", "ntds.dit",
        ),
        "technique_boost": 0.1,
    },
    "discovery": {
        "label": "Discovery",
        "techniques": ("T1087", "T1046", "T1082", "T1040"),
        "searches": (
            "whoami", "net user", "nmap", "netstat", "systeminfo",
            "promiscuous", "sniffing", "arp -a", "getent passwd",
            "cat /etc/passwd", "port scan",
        ),
        "technique_boost": 0.07,
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "techniques": ("T1021", "T1570", "T1550", "T1210", "T1105"),
        "searches": (
            "psexec", "winrm", "smbclient", "pass-the-hash", "mstsc",
            "crackmapexec", "wmiexec", "scp ", "rsync ", "4648",
        ),
        "technique_boost": 0.09,
    },
}

# IA vector attribution — sxsecurityinvestigator initial_access._VECTOR_BY_TECHNIQUE.
_VECTOR_BY_TECHNIQUE: dict[str, str] = {
    "T1078": "valid_account",
    "T1110": "brute_force",
    "T1133": "external_remote_service",
    "T1190": "exploit_public_facing",
    "T1566": "phishing",
    "T1189": "drive_by",
}

_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _boundary_pattern(term: str) -> re.Pattern[str]:
    """Word-boundary pattern: ``usb`` must not match ``usb-storage``."""
    return re.compile(rf"(?<![\w-]){re.escape(term.strip())}(?![\w-])")


_SEARCH_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    phase: [(term, _boundary_pattern(term)) for term in spec["searches"]]
    for phase, spec in PHASE_SPECS.items()
}


def _event_text(event: dict[str, Any]) -> str:
    raw = event.get("raw") or {}
    parts = [
        str(event.get("title") or ""),
        str(event.get("description") or ""),
        str(event.get("full_log") or ""),
        str(event.get("message") or ""),
        str(event.get("command_line") or ""),
        str(event.get("action") or ""),
        str(raw.get("description") or ""),
        str(raw.get("full_log") or ""),
        str(raw.get("command_line") or ""),
        str(raw.get("alert_name") or ""),
    ]
    return " ".join(parts).lower()


def _event_host(event: dict[str, Any]) -> str | None:
    raw = event.get("raw") or {}
    device = raw.get("device") or event.get("device") or {}
    host = (
        event.get("host")
        or event.get("hostname")
        or raw.get("agent_host")
        or raw.get("hostname")
        or (device.get("name") if isinstance(device, dict) else None)
    )
    return str(host) if host else None


def _event_time(event: dict[str, Any]) -> str | None:
    raw = event.get("raw") or {}
    ts = event.get("timestamp") or event.get("time") or raw.get("time") or raw.get("@timestamp")
    return str(ts) if ts else None


def _event_techniques(event: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    raw = event.get("raw") or {}
    for source in (event, raw):
        for key in ("mitre_techniques", "techniques", "mitre_technique_id", "mitre_mappings"):
            val = source.get(key)
            if not val:
                continue
            items = val if isinstance(val, (list, tuple)) else [val]
            for item in items:
                found.update(_TECHNIQUE_ID_RE.findall(str(item).upper()))
    return found


async def _probe_searches(
    phase: str, events: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], str]]:
    """Find events whose text hits a phase search term (word-boundary match)."""
    await asyncio.sleep(0)  # genuine concurrency inside asyncio.gather
    hits: list[tuple[dict[str, Any], str]] = []
    for event in events:
        text = _event_text(event)
        for term, pattern in _SEARCH_PATTERNS[phase]:
            if pattern.search(text):
                hits.append((event, term))
                break  # one hit per event is enough
    return hits


async def _probe_techniques(
    phase: str, events: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], str]]:
    """Find events carrying one of the phase's MITRE techniques."""
    await asyncio.sleep(0)
    wanted = set(PHASE_SPECS[phase]["techniques"])
    hits: list[tuple[dict[str, Any], str]] = []
    for event in events:
        matched = _event_techniques(event) & wanted
        if matched:
            hits.append((event, sorted(matched)[0]))
    return hits


async def _hunt_phase(
    phase: str,
    events: list[dict[str, Any]],
    anchor_host: str | None,
) -> KillChainPhase:
    spec = PHASE_SPECS[phase]
    verdict = KillChainPhase(name=spec["label"])

    search_hits, technique_hits = await asyncio.gather(
        _probe_searches(phase, events),
        _probe_techniques(phase, events),
    )

    if not search_hits and not technique_hits:
        return verdict  # unconfirmed, confidence 0.0 — honest default

    # Score: distinct search terms + technique corroboration + anchor proximity.
    distinct_terms = {term for _, term in search_hits}
    matched_techniques = {tech for _, tech in technique_hits}
    score = min(len(distinct_terms) * 0.2, 0.5)
    score += min(len(matched_techniques) * spec["technique_boost"] * 2, 0.3)
    hit_events = [e for e, _ in search_hits] + [e for e, _ in technique_hits]
    if anchor_host and any(_event_host(e) == anchor_host for e in hit_events):
        score += 0.15  # activity on the chained anchor host corroborates
    score = min(score, 0.95)

    # Status requires ≥2 independent signals for confirmed — a single
    # keyword/technique hit is never a confirmed phase.
    signals = len(distinct_terms) + len(matched_techniques)
    if signals >= 3 and score >= 0.6:
        verdict.status = "confirmed"
    elif signals >= 2 and score >= 0.4:
        verdict.status = "likely"
    else:
        verdict.status = "suspected"
    verdict.confidence = round(score, 2)
    verdict.mitre_techniques = sorted(matched_techniques)

    if phase == "initial_access":
        for tech in verdict.mitre_techniques:
            base = tech.split(".")[0]
            if base in _VECTOR_BY_TECHNIQUE:
                verdict.vector = _VECTOR_BY_TECHNIQUE[base]
                break

    # Entry attribution: earliest-timestamped hit event on a real host.
    timed = sorted(
        ((e, _event_time(e)) for e in hit_events if _event_time(e)),
        key=lambda pair: pair[1],  # ISO strings sort chronologically
    )
    anchor_event = timed[0][0] if timed else hit_events[0]
    verdict.entry_host = _event_host(anchor_event)
    verdict.entry_time = _event_time(anchor_event)

    for event, term in search_hits[:3]:
        host = _event_host(event) or "unknown"
        verdict.findings.append(f"{host}: matched '{term}'")
    for event, tech in technique_hits[:3]:
        host = _event_host(event) or "unknown"
        verdict.findings.append(f"{host}: technique {tech}")
    verdict.candidates = [
        {"entity": f"host:{verdict.entry_host}", "score": verdict.confidence, "vector": verdict.vector}
    ] if verdict.entry_host else []
    return verdict


async def run_phase_hunts(
    events: list[Any],
    raw_alert: dict[str, Any] | None = None,
) -> dict[str, KillChainPhase]:
    """Hunt all five kill-chain phases in order with anchor chaining.

    ``events`` should already be noise-tagged; tagged events are skipped.
    The originating alert participates as an event too.
    """
    corpus: list[dict[str, Any]] = []
    if raw_alert:
        corpus.append(raw_alert)
    corpus.extend(e for e in events if isinstance(e, dict))
    signal = [e for e in corpus if not e.get("noise")]

    verdicts: dict[str, KillChainPhase] = {}
    anchor_host: str | None = None
    for phase in PHASE_ORDER:
        verdict = await _hunt_phase(phase, signal, anchor_host)
        verdicts[phase] = verdict
        if verdict.status in ("confirmed", "likely") and verdict.entry_host:
            anchor_host = verdict.entry_host  # chain the anchor forward
    return verdicts


def summarize_phase_verdicts(verdicts: dict[str, KillChainPhase]) -> str:
    """One-line kill-chain summary for findings / the Forensic card."""
    asserted = [
        v for v in verdicts.values() if v.status in ("confirmed", "likely")
    ]
    if not asserted:
        suspected = [v for v in verdicts.values() if v.status == "suspected"]
        if suspected:
            bits = ", ".join(f"{v.name} ({v.confidence:.2f})" for v in suspected)
            return f"Kill chain: no phase confirmed — weak signals only: {bits}"
        return "Kill chain: no phase confirmed — no attack progression identified"
    bits = []
    for v in asserted:
        vec = f" via {v.vector}" if v.vector and v.vector != "unknown" else ""
        bits.append(f"{v.name} {v.status}{vec} ({v.confidence:.2f})")
    return "Kill chain: " + "; ".join(bits)
