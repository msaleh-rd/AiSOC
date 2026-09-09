#!/usr/bin/env python3
"""Ingest real Wazuh / Suricata log data into a running local AiSOC stack.

This is a one-off, host-side importer for testing AiSOC against *real*
telemetry instead of the seeded demo dataset. It reads native log files from
a directory tree (Wazuh alert JSON-lines + Suricata eve.json) and pushes them
through the same public ingest contract every connector uses
(``POST /v1/ingest/batch`` on the Go ingest service), so the events flow
through the real pipeline: ingest -> Kafka -> fusion (OCSF promote/fuse) ->
Postgres alerts -> realtime WS -> the Alerts UI.

Not a connector, not wired into the scheduler, no dependency on the
`services/connectors` package — deliberately standalone so it can run with a
stock Python 3 interpreter against a directory of exported log files.

Usage (from repo root, with `docker compose up -d` already running):

    python scripts/ingest_local_logs.py --root "D:\\path\\to\\CAM-LDS-team-messy"

Options:
    --root          Path to the log export root (expects security/ and
                     network/ subdirectories with Wazuh + Suricata files).
    --ingest-url    Base URL of the Go ingest service (default matches the
                     port mapping in docker-compose.yml: http://localhost:8081)
    --tenant-id     Tenant UUID to ingest under (default: the seeded demo
                     tenant 00000000-0000-0000-0000-000000000001, so the
                     alerts show up immediately in the already-logged-in UI)
    --dry-run       Parse and print counts without POSTing anything

Sources handled in this first pass:
    security/wazuh__alerts_*.json      native Wazuh alert JSON-lines
    network/*_suricata_eve.json        Suricata eve.json, event_type=="alert" only

Explicitly out of scope for this pass (left as raw files, not ingested):
    audit.log (auditd multi-record reassembly), collectd, syslog, apache/exim,
    apt history. These have real signal but need more per-format mapping work
    than a first smoke-test warrants.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_INGEST_URL = "http://localhost:8081"
BATCH_SIZE = 500

# Wazuh 0-15 rule level -> AiSOC 5-tier ladder. Mirrors
# services/connectors/app/connectors/wazuh.py _SEVERITY_BANDS so an operator
# who later wires up a live Wazuh indexer connector sees the same mapping
# this one-off import produced.
_WAZUH_SEVERITY_BANDS: tuple[tuple[int, str], ...] = (
    (15, "critical"),
    (12, "high"),
    (8, "medium"),
    (4, "low"),
    (0, "info"),
)

# Suricata alert.severity (1=highest) -> AiSOC ladder. Mirrors
# services/connectors/app/connectors/zeek_suricata.py _SURICATA_SEV.
_SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low"}


def _wazuh_severity(level: int) -> str:
    for threshold, label in _WAZUH_SEVERITY_BANDS:
        if level >= threshold:
            return label
    return "info"


def _hostname_from_filename(path: Path) -> str:
    # Files are named "<host>__log_<rest>", e.g. "corpdns__log_auth.log".
    return path.name.split("__", 1)[0]


def load_wazuh_events(path: Path) -> list[dict[str, Any]]:
    """Parse a native Wazuh alert JSON-lines file into canonical events."""
    hostname = _hostname_from_filename(path)
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(f"  ! {path.name}:{line_no}: skipping malformed JSON line", file=sys.stderr)
                continue

            rule = raw.get("rule") or {}
            agent = raw.get("agent") or {}
            level = int(rule.get("level", 0) or 0)
            mitre = rule.get("mitre") or {}
            techniques = mitre.get("id") if isinstance(mitre.get("id"), list) else []
            tactics = mitre.get("tactic") if isinstance(mitre.get("tactic"), list) else []

            alert_id = raw.get("id") or f"{rule.get('id', 'unknown')}::{raw.get('timestamp', '')}"

            events.append(
                {
                    "source": "wazuh",
                    "category": "siem",
                    "event_type": "wazuh_alert",
                    "severity": _wazuh_severity(level),
                    "title": rule.get("description") or "Wazuh alert",
                    "description": (raw.get("full_log") or rule.get("description") or "")[:1000],
                    "alert_id": alert_id,
                    "rule_id": rule.get("id"),
                    "rule_level": level,
                    "mitre_techniques": techniques,
                    "mitre_tactics": tactics,
                    "hostname": agent.get("name") or hostname,
                    "agent_id": agent.get("id"),
                    "created_at": raw.get("timestamp"),
                    "raw_event": raw,
                }
            )
    return events


def load_suricata_alert_events(path: Path) -> list[dict[str, Any]]:
    """Parse a Suricata eve.json file, keeping only event_type == 'alert'."""
    hostname = _hostname_from_filename(path)
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(f"  ! {path.name}:{line_no}: skipping malformed JSON line", file=sys.stderr)
                continue

            if raw.get("event_type") != "alert":
                continue

            alert = raw.get("alert") or {}
            sev_raw = alert.get("severity", 3)
            sev_num = int(sev_raw) if str(sev_raw).isdigit() else 3
            severity = _SURICATA_SEVERITY.get(sev_num, "low")

            events.append(
                {
                    "source": "suricata",
                    "category": "ndr",
                    "event_type": "zeek_suricata.suricata.alert",
                    "severity": severity,
                    "title": alert.get("signature") or "Suricata alert",
                    "description": (
                        f"category={alert.get('category')}; "
                        f"sid={alert.get('signature_id')}; proto={raw.get('proto')}"
                    ),
                    "external_id": str(raw.get("flow_id") or alert.get("signature_id") or ""),
                    "src_ip": raw.get("src_ip"),
                    "src_port": raw.get("src_port"),
                    "dst_ip": raw.get("dest_ip"),
                    "dst_port": raw.get("dest_port"),
                    "hostname": hostname,
                    "created_at": raw.get("timestamp"),
                    "raw_event": raw,
                }
            )
    return events


def post_batch(
    ingest_url: str,
    tenant_id: str,
    connector_id: str,
    connector_type: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    body = json.dumps(
        {
            "connector_id": connector_id,
            "connector_type": connector_type,
            "source_format": "raw_json",
            "events": events,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{ingest_url.rstrip('/')}/v1/ingest/batch",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Tenant-ID": tenant_id,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ingest POST failed ({exc.code}): {detail}") from exc


def ingest_events(
    label: str,
    events: list[dict[str, Any]],
    *,
    ingest_url: str,
    tenant_id: str,
    connector_id: str,
    connector_type: str,
    dry_run: bool,
) -> None:
    print(f"[{label}] {len(events)} events parsed")
    if dry_run or not events:
        return

    accepted = 0
    rejected = 0
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i : i + BATCH_SIZE]
        result = post_batch(ingest_url, tenant_id, connector_id, connector_type, batch)
        accepted += result.get("accepted", 0)
        rejected += result.get("rejected", 0)
        if result.get("errors"):
            for err in result["errors"][:5]:
                print(f"  ! {label}: {err}", file=sys.stderr)
    print(f"[{label}] accepted={accepted} rejected={rejected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", required=True, help="Path to the log export root")
    parser.add_argument("--ingest-url", default=DEFAULT_INGEST_URL)
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 1

    security_dir = root / "security"
    network_dir = root / "network"

    wazuh_files = sorted(security_dir.glob("*_ossec-alerts-*.json"))
    suricata_files = sorted(network_dir.glob("*_suricata_eve.json"))

    if not wazuh_files:
        print(f"warning: no Wazuh alert files matched under {security_dir}", file=sys.stderr)
    if not suricata_files:
        print(f"warning: no Suricata eve.json files matched under {network_dir}", file=sys.stderr)

    wazuh_events: list[dict[str, Any]] = []
    for f in wazuh_files:
        wazuh_events.extend(load_wazuh_events(f))

    suricata_events: list[dict[str, Any]] = []
    for f in suricata_files:
        suricata_events.extend(load_suricata_alert_events(f))

    print(f"root: {root}")
    print(f"tenant: {args.tenant_id}")
    print(f"wazuh files: {[f.name for f in wazuh_files]}")
    print(f"suricata files: {[f.name for f in suricata_files]}")
    print()

    ingest_events(
        "wazuh",
        wazuh_events,
        ingest_url=args.ingest_url,
        tenant_id=args.tenant_id,
        connector_id="sxsi-local-import-wazuh",
        connector_type="wazuh",
        dry_run=args.dry_run,
    )
    ingest_events(
        "suricata",
        suricata_events,
        ingest_url=args.ingest_url,
        tenant_id=args.tenant_id,
        connector_id="sxsi-local-import-suricata",
        connector_type="zeek_suricata",
        dry_run=args.dry_run,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
