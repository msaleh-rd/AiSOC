"""Noise tagging for compliance/benchmark telemetry.

Ported from sxsecurityinvestigator's investigation_manager noise filters
(``_NOISE_RULE_GROUPS`` / ``_NOISE_HOSTS`` / ``_NOISE_PROCESS_TOKENS``).

Compliance-scan output (CIS benchmark checks, SCA summaries, rootcheck,
policy monitoring) is *context*, not attack evidence. It must stay visible
in reports, but it must never feed hypothesis matching — a CIS line like
"Ensure usb-storage kernel module is not available" previously matched the
insider-exfiltration hypothesis keyword ``usb`` and produced a false swarm
winner. Events are therefore **tagged** (``noise: True``), never dropped.
"""

from __future__ import annotations

from typing import Any

_NOISE_RULE_GROUPS = frozenset(
    {"sca", "rootcheck", "cis", "policy_monitoring", "compliance"}
)

_NOISE_HOSTS = frozenset({"wazuh", "wazuh-manager", "siem"})

_NOISE_PROCESS_TOKENS = (
    "ansiballz_systemd",
    "mate-power-mana",
    "mate-power-manager",
    "unattended-upgrade",
    "cloud-init",
)

# Text markers for compliance-scan output when structured rule groups are
# unavailable on normalized platform alerts.
_NOISE_TEXT_MARKERS = (
    "cis ubuntu",
    "cis benchmark",
    "benchmark v",
    "sca summary",
    "policy_monitoring",
    "rootcheck",
    "ensure permissions on /etc/",
    "ensure kernel module",
    "is not available.",  # "Ensure <module> kernel module is not available."
)


def _event_text(event: dict[str, Any]) -> str:
    raw = event.get("raw") or {}
    parts = [
        str(event.get("title") or ""),
        str(event.get("description") or ""),
        str(event.get("full_log") or ""),
        str(event.get("message") or ""),
        str(raw.get("description") or ""),
        str(raw.get("full_log") or ""),
        str(raw.get("alert_name") or ""),
    ]
    return " ".join(parts).lower()


def is_noise(event: dict[str, Any]) -> bool:
    """Return True when the event is compliance/maintenance noise."""
    if not isinstance(event, dict):
        return False
    raw = event.get("raw") or {}

    groups = event.get("rule_groups") or raw.get("rule_groups") or raw.get("groups") or []
    for g in groups:
        if str(g).lower() in _NOISE_RULE_GROUPS:
            return True

    host = str(event.get("host") or event.get("hostname") or raw.get("agent_host") or "").lower()
    if host in _NOISE_HOSTS:
        return True

    proc = str(event.get("process") or raw.get("process_name") or raw.get("command_line") or "").lower()
    if proc and any(tok in proc for tok in _NOISE_PROCESS_TOKENS):
        return True

    text = _event_text(event)
    return any(marker in text for marker in _NOISE_TEXT_MARKERS)


def tag_noise(events: list[Any]) -> tuple[int, int]:
    """Tag noise events in place with ``noise: True``.

    Returns ``(noise_count, signal_count)``.
    """
    noise = 0
    signal = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("noise") is True or is_noise(event):
            event["noise"] = True
            noise += 1
        else:
            signal += 1
    return noise, signal


def signal_events(events: list[Any]) -> list[dict[str, Any]]:
    """Return only the non-noise dict events."""
    return [e for e in events if isinstance(e, dict) and not e.get("noise")]
