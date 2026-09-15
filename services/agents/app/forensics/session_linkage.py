"""Session & Identity Linkage engine.

Ported from sxsecurityinvestigator: extracts explicit logon session IDs
(Windows LogonID 0x..., Kerberos Ticket IDs 4768/4769, and Linux/Wazuh SSH session PIDs/tokens)
from event raw data to link cross-host activities and establish session attribution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionToken:
    """Extracted session identifier for cross-event linkage."""

    session_id: str          # e.g. "logon_id:0x1f23a", "ssh_pid:1234", "kerberos:4768:user1"
    session_type: str        # "windows_logon", "kerberos_ticket", "ssh_session", "pam_session"
    user: str | None = None
    host: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type,
            "user": self.user,
            "host": self.host,
            "metadata": self.metadata,
        }


def _extract_val(item: Any, *keys: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        for k in keys:
            if k in item and item[k] is not None:
                return item[k]
        raw = item.get("raw")
        if isinstance(raw, dict):
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
    else:
        for k in keys:
            val = getattr(item, k, None)
            if val is not None:
                return val
        raw = getattr(item, "raw", None)
        if isinstance(raw, dict):
            for k in keys:
                if k in raw and raw[k] is not None:
                    return raw[k]
    return default


def extract_session_tokens(event: Any) -> list[SessionToken]:
    """Extract explicit session tokens from an event or alert."""
    tokens: list[SessionToken] = []

    host = str(_extract_val(event, "host", "hostname", "affected_host", "device_name", default=""))
    user = str(_extract_val(event, "user", "username", "account", "src_user", "target_user", default=""))

    raw = event.get("raw", event) if isinstance(event, dict) else getattr(event, "raw", {})
    if not isinstance(raw, dict):
        raw = {}

    # 1. Windows LogonID (e.g. TargetLogonId, SubjectLogonId, LogonId)
    for key in ("TargetLogonId", "SubjectLogonId", "LogonId", "TargetLogonID", "SubjectLogonID", "logon_id"):
        logon_id = raw.get(key)
        # Exclude reserved/system logon sessions (SYSTEM=0x3e7, NETWORK SERVICE=0x3e4, etc.)
        if logon_id and str(logon_id).lower() not in ("0x0", "0x3e7", "0x3e4", "0x3e5", "0", "-", "none"):
            sid = str(logon_id).lower()
            tokens.append(SessionToken(
                session_id=f"logon_id:{sid}",
                session_type="windows_logon",
                user=user or None,
                host=host or None,
                metadata={"raw_key": key, "raw_id": logon_id},
            ))

    # 2. Windows Kerberos EventIDs (4768 TGT Request, 4769 ST Request, 4771 Auth Failure)
    event_id = str(raw.get("EventID") or raw.get("event_id") or "")
    if event_id in ("4768", "4769", "4771"):
        tgt_user = str(raw.get("TargetUserName") or raw.get("TargetUserSid") or user or "")
        ticket_id = raw.get("TicketOptions") or raw.get("TicketEncryptionType")
        if tgt_user and tgt_user != "-":
            tokens.append(SessionToken(
                session_id=f"kerberos:{event_id}:{tgt_user.lower()}",
                session_type="kerberos_ticket",
                user=tgt_user,
                host=host or None,
                metadata={"event_id": event_id, "ticket_info": ticket_id},
            ))

    # 3. SSH Session tokens (Linux auth logs / Wazuh: sshd[PID] or process ID)
    process_str = str(
        _extract_val(event, "process", "process_name", default="")
        or raw.get("process")
        or raw.get("message")
        or raw.get("full_log")
        or ""
    )
    ssh_match = re.search(r"sshd(?:\[(\d+)\]|:session|\s+(\d+))", process_str, re.IGNORECASE)
    if ssh_match:
        pid = ssh_match.group(1) or ssh_match.group(2) or str(_extract_val(event, "pid", default=""))
        if pid:
            tokens.append(SessionToken(
                session_id=f"ssh_pid:{pid}",
                session_type="ssh_session",
                user=user or None,
                host=host or None,
                metadata={"pid": pid, "source": "sshd"},
            ))

    # 4. Linux PAM session logs
    pam_match = re.search(r"pam_unix\([^)]+\):\s+session\s+(opened|closed)\s+for\s+user\s+(\w+)", process_str, re.IGNORECASE)
    if pam_match:
        action, pam_user = pam_match.group(1), pam_match.group(2)
        tokens.append(SessionToken(
            session_id=f"pam:{host}:{pam_user}",
            session_type="pam_session",
            user=pam_user,
            host=host or None,
            metadata={"action": action},
        ))

    return tokens


def group_events_by_session(events: list[Any]) -> dict[str, list[Any]]:
    """Group events by extracted session identifiers."""
    sessions: dict[str, list[Any]] = {}
    for event in events:
        tokens = extract_session_tokens(event)
        for token in tokens:
            sessions.setdefault(token.session_id, []).append(event)
    return sessions
