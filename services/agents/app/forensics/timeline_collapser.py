"""Timeline noise collapsing, scan storm suppression, and event burst aggregation.

Ported from sxsecurityinvestigator/investigator/reporting/timeline_builder.py
for AiSOC. Suppresses compliance/SCA scans (Lynis, CIS, policy sweeps) and collapses
identical cron/daemon repetitions into concise (xN, through ...) entries.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any

from app.forensics.models import TimelineEntry

# Rule groups that indicate compliance/SCA scan activity, not attack events.
_COMPLIANCE_GROUPS = frozenset({
    "sca", "rootcheck", "cis", "policy_monitoring", "policy_changed",
    "audit_configuration",
})

# CIS-benchmark text markers
_CIS_TEXT_MARKERS = (
    "cis ubuntu linux", "cis debian linux", "cis red hat",
    "cis oracle linux", "cis centos linux", "cis distribution independent",
    "cis benchmark", "sca-check",
)

# Audit/compliance scan storms (Lynis/CIS-style sweeps), boot chatter, and cert updates:
# hundreds of stat/dpkg-query/systemctl-status executions per scan plus kernel
# dmesg replays that carry no detection value. Events matching these patterns
# are dropped only while their score stays below _AUDIT_SCAN_SCORE_CEILING —
# anything a detector meaningfully flagged survives regardless of name.
_AUDIT_SCAN_SCORE_CEILING = 40.0

_AUDIT_SCAN_PROCESSES = frozenset({
    "stat", "dpkg-query", "which", "grep", "sed", "awk", "cut",
    "head", "tail", "wc", "uname", "id", "hostname", "uptime",
})

_AUDIT_SCAN_CMD_PREFIXES = (
    "sshd -t",            # sshd -t / sshd -T config probes (lowercased)
    "/usr/sbin/sshd -t",
    "sshd -d",            # sshd -D daemon / per-connection re-exec forks
    "/usr/sbin/sshd -d",
    "stat -",             # stat -L / stat -c / stat -Lc permission sweeps
    "gpgv ",
    "/bin/sh /usr/bin/apt-key",
    "nsenter -t 1 -m systemctl",
    "cmp -s etc/ssl/certs",
    "cmp -s",
    "/usr/bin/openssl x509",
    "openssl x509",
    "openssl req -config",
    "/usr/sbin/postconf -c /etc/postfix",
    "/usr/bin/file --mime-type",
    "find /etc/audit/",
    "find /var/lib/apt/lists/",
    "logger -s -p user.info -t cloud-init",
    "mktemp -d /var/tmp/cloud-init/",
    "head -n 1 /opt/puppetlabs/",
    "mount -t squashfs /tmp/syscheck-",
    "umount -l /tmp/syscheck-",
    "readlink -f /tmp/apt-key-gpghome",
    "chmod 700 /tmp/apt-key-gpghome",
    "touch /tmp/apt-key-gpghome",
    "cp -a /tmp/apt-key-gpghome",
    "dd if=/dev/zero of=/tmp/whitespace",
    "sfdisk --no-reread",
    "/opt/puppetlabs/puppet/bin/ruby /opt/puppetlabs/puppet/bin/puppet agent",
    "/opt/puppetlabs/puppet/bin/ruby /opt/puppetlabs/server/data/puppetserver/dropsonde",
)

_BENIGN_OS_CMD_MARKERS = (
    "/var/tmp/mkinitramfs_",
    "gds: unknown: dependent on hypervisor",
    "x86/fpu: xstate_offset",
    "x86/fpu: enabled xstate features",
    "audit: type=2000",
    "audit: type=1400",
    "registered taskstats version",
    "intel_pstate: cpu model not supported",
    "key type encrypted registered",
    "growpart.xxxxxx",
)
_BENIGN_OS_SCORE_CEILING = 120.0


def _parse_ts(val: Any) -> datetime | None:
    if isinstance(val, datetime):
        return val
    if not val or not isinstance(val, str):
        return None
    try:
        # Handle trailing Z or offset
        cleaned = val.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


@dataclass
class _Group:
    representative: dict[str, Any]
    description: str
    event_type: str
    host: str
    count: int
    first: datetime
    last: datetime
    max_score: float


class TimelineCollapser:
    """Collapses duplicate events and produces a noise-filtered, representative timeline."""

    def __init__(self, max_entries: int = 50):
        self.max_entries = max_entries

    def build_timeline(
        self,
        events: list[dict[str, Any]],
        max_entries: int | None = None,
    ) -> list[TimelineEntry]:
        limit = max_entries or self.max_entries
        if not events:
            return []

        # Filter out compliance & benign OS noise
        valid_events: list[dict[str, Any]] = []
        for e in events:
            ts = _parse_ts(e.get("timestamp") or e.get("@timestamp") or e.get("time"))
            if not ts:
                continue
            if self._is_compliance_noise(e) or self._is_audit_scan_noise(e):
                continue
            valid_events.append(e)

        if not valid_events:
            # Fallback: if all events were filtered as noise, keep original timestamped ones
            valid_events = [
                e for e in events
                if _parse_ts(e.get("timestamp") or e.get("@timestamp") or e.get("time"))
            ]

        if not valid_events and events:
            now_ts = datetime.now(timezone.utc).isoformat()
            valid_events = [{**e, "timestamp": now_ts} for e in events]

        if not valid_events:
            return []

        groups = self._collapse(valid_events)
        selected = self._select(groups, limit)
        selected.sort(key=lambda g: g.first)

        entries: list[TimelineEntry] = []
        for g in selected:
            desc = g.description
            end_ts_str = None
            if g.count > 1:
                end_ts_str = g.last.isoformat()
                if g.first != g.last:
                    desc = f"{desc} (x{g.count}, through {end_ts_str})"
                else:
                    desc = f"{desc} (x{g.count})"

            entries.append(
                TimelineEntry(
                    timestamp=g.first.isoformat(),
                    host=g.host,
                    event_type=g.event_type,
                    score=round(g.max_score, 2),
                    description=desc,
                    count=g.count,
                    end_timestamp=end_ts_str,
                )
            )
        return entries

    def _collapse(self, events: list[dict[str, Any]]) -> list[_Group]:
        groups: dict[tuple, _Group] = {}

        for e in events:
            ts = _parse_ts(e.get("timestamp") or e.get("@timestamp") or e.get("time"))
            if not ts:
                continue

            host = str(e.get("host") or e.get("hostname") or e.get("agent_host") or "unknown")
            event_type = str(e.get("event_type") or e.get("category") or e.get("type") or "activity")
            score = float(e.get("score") or e.get("risk_score") or 0.0)
            desc = self._describe(e)

            burst_group = e.get("burst_group")
            if burst_group is not None:
                signature = ("__burst__", host, str(burst_group))
            else:
                signature = (host, event_type, desc)

            existing = groups.get(signature)
            if existing is None:
                groups[signature] = _Group(
                    representative=e,
                    description=desc,
                    event_type=event_type,
                    host=host,
                    count=1,
                    first=ts,
                    last=ts,
                    max_score=score,
                )
            else:
                existing.count += 1
                if ts < existing.first:
                    existing.first = ts
                if ts > existing.last:
                    existing.last = ts
                if score > existing.max_score:
                    existing.max_score = score
                    existing.representative = e

        return list(groups.values())

    def _select(self, groups: list[_Group], limit: int) -> list[_Group]:
        if len(groups) <= limit:
            return groups

        ranked = sorted(
            groups,
            key=lambda g: (g.max_score, g.count, g.last),
            reverse=True,
        )

        scored = [g for g in ranked if g.max_score > 0]
        unscored = [g for g in ranked if g.max_score <= 0]

        selected: list[_Group] = scored[:limit]
        if len(selected) >= limit:
            return selected[:limit]

        remaining = limit - len(selected)
        selected.extend(self._interleave_by_type(unscored, remaining))
        return selected

    def _interleave_by_type(self, groups: list[_Group], count: int) -> list[_Group]:
        if count <= 0 or not groups:
            return []

        buckets: dict[str, list[_Group]] = {}
        for group in groups:
            buckets.setdefault(group.event_type, []).append(group)

        order = sorted(buckets, key=lambda t: -len(buckets[t]))
        picked: list[_Group] = []
        exhausted = False
        while len(picked) < count and not exhausted:
            exhausted = True
            for event_type in order:
                bucket = buckets[event_type]
                if bucket:
                    picked.append(bucket.pop(0))
                    exhausted = False
                    if len(picked) >= count:
                        break
        return picked

    def _describe(self, event: dict[str, Any]) -> str:
        raw = event.get("raw") or event
        cmd = raw.get("command_line") or raw.get("cmd")
        desc = (
            raw.get("description")
            or raw.get("desc")
            or raw.get("summary")
            or raw.get("rule_name")
            or raw.get("RuleTitle")
            or cmd
            or raw.get("process_name")
            or raw.get("action")
            or event.get("alert_name")
            or str(event.get("event_type") or "activity")
        )
        desc_str = str(desc).strip()
        if cmd and str(cmd).strip() != desc_str and raw.get("description"):
            return f"{desc_str}: {str(cmd).strip()}"
        return desc_str

    def _is_compliance_noise(self, event: dict[str, Any]) -> bool:
        raw = event.get("raw") or event
        rule = raw.get("rule") or {}
        groups = rule.get("groups") if isinstance(rule, dict) else None
        if isinstance(groups, list):
            for g in groups:
                if str(g).lower() in _COMPLIANCE_GROUPS:
                    return True

        text = (str(raw.get("description") or "") + " " + str(raw.get("full_log") or "")).lower()
        for marker in _CIS_TEXT_MARKERS:
            if marker in text:
                return True
        return False

    def _is_audit_scan_noise(self, event: dict[str, Any]) -> bool:
        score = float(event.get("score") or event.get("risk_score") or 0.0)
        if score >= _BENIGN_OS_SCORE_CEILING:
            return False

        raw = event.get("raw") or event
        cmd = str(raw.get("command_line") or raw.get("cmd") or raw.get("full_log") or "").lower()
        proc = str(raw.get("process_name") or raw.get("process") or "").lower()

        if score < _AUDIT_SCAN_SCORE_CEILING:
            if proc in _AUDIT_SCAN_PROCESSES:
                return True
            for prefix in _AUDIT_SCAN_CMD_PREFIXES:
                if cmd.startswith(prefix) or f" {prefix}" in cmd:
                    return True

        for marker in _BENIGN_OS_CMD_MARKERS:
            if marker in cmd:
                return True

        return False
