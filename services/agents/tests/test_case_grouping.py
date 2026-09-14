"""Tests for agents-service auto_group_alert worker."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.workers.case_grouping import auto_group_alert, max_severity


class MockAsyncpgConnection:
    def __init__(self):
        self.cases: dict[uuid.UUID, dict[str, Any]] = {}
        self.alerts: dict[uuid.UUID, dict[str, Any]] = {}
        self.comments: list[dict[str, Any]] = []

    async def fetchrow(self, query: str, *args):
        tenant_id = args[0]
        cutoff = args[1]
        chain_id = args[2]
        entity_keys = args[3] if len(args) > 3 else []
        hosts = args[4] if len(args) > 4 else None
        ips = args[5] if len(args) > 5 else None
        users = args[6] if len(args) > 6 else None

        for c in self.cases.values():
            if c["tenant_id"] != tenant_id:
                continue
            if c["status"] not in ("new", "triaged", "investigating"):
                continue
            if cutoff and c["updated_at"] < cutoff:
                continue

            # Check chain_id
            tags = c.get("tags") or {}
            if chain_id and tags.get("chain_id") == chain_id:
                return c

            # Check primary entity
            if tags.get("primary_entity") in entity_keys:
                return c

            # Check entity overlap in linked alerts
            for aid in c.get("alert_ids", []):
                alert = self.alerts.get(aid)
                if alert:
                    if hosts and any(h in (alert.get("affected_hosts") or []) for h in hosts):
                        return c
                    if ips and any(i in (alert.get("affected_ips") or []) for i in ips):
                        return c
                    if users and any(u in (alert.get("affected_users") or []) for u in users):
                        return c

        return None

    async def execute(self, query: str, *args):
        query_strip = query.strip()
        if query_strip.startswith("UPDATE aisoc_cases"):
            # Args: [alert_id], new_severity, json.dumps(combined_mitre), case_id, tenant_id
            new_ids = args[0]
            new_severity = args[1]
            mitre_json = args[2]
            case_id = args[3]
            if case_id in self.cases:
                existing = self.cases[case_id].get("alert_ids", [])
                for nid in new_ids:
                    if nid not in existing:
                        existing.append(nid)
                self.cases[case_id]["alert_ids"] = existing
                self.cases[case_id]["severity"] = new_severity
                self.cases[case_id]["mitre_techniques"] = json.loads(mitre_json)
                self.cases[case_id]["updated_at"] = datetime.now(UTC)
        elif query_strip.startswith("INSERT INTO aisoc_cases"):
            # Args: id, tenant_id, case_number, title, description, severity, mitre, alert_ids, tags
            cid = args[0]
            self.cases[cid] = {
                "id": cid,
                "tenant_id": args[1],
                "case_number": args[2],
                "title": args[3],
                "description": args[4],
                "severity": args[5],
                "status": "new",
                "mitre_techniques": json.loads(args[6]),
                "alert_ids": list(args[7]),
                "tags": json.loads(args[8]),
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
        elif query_strip.startswith("UPDATE alerts"):
            case_id = args[0]
            alert_id = args[1]
            if alert_id in self.alerts:
                self.alerts[alert_id]["case_id"] = case_id
        elif query_strip.startswith("INSERT INTO aisoc_case_comments"):
            self.comments.append({"case_id": args[0], "body": args[2]})


@pytest.mark.asyncio
async def test_auto_group_alert_creates_and_groups():
    conn = MockAsyncpgConnection()
    tenant_id = uuid.uuid4()

    # 1. First alert: Firewall port scan on inetfw
    a1_id = uuid.uuid4()
    a1 = {
        "id": str(a1_id),
        "title": "Firewall Port Scan",
        "severity": "medium",
        "affected_hosts": ["inetfw"],
        "mitre_techniques": ["T1046"],
    }
    conn.alerts[a1_id] = dict(a1)

    r1 = await auto_group_alert(conn, alert_id=a1_id, tenant_id=tenant_id, raw_alert=a1)
    assert r1["action"] == "created"
    assert r1["is_new_case"] is True
    assert r1["linked_alert_count"] == 1
    case_id = uuid.UUID(r1["case_id"])
    assert case_id in conn.cases

    # 2. Second alert: SSH brute force on inetfw
    a2_id = uuid.uuid4()
    a2 = {
        "id": str(a2_id),
        "title": "SSH Brute Force",
        "severity": "high",
        "affected_hosts": ["inetfw"],
        "mitre_techniques": ["T1110"],
    }
    conn.alerts[a2_id] = dict(a2)

    r2 = await auto_group_alert(conn, alert_id=a2_id, tenant_id=tenant_id, raw_alert=a2)
    assert r2["action"] == "grouped"
    assert r2["is_new_case"] is False
    assert r2["case_id"] == str(case_id)
    assert r2["linked_alert_count"] == 2

    # Verify case state
    c = conn.cases[case_id]
    assert len(c["alert_ids"]) == 2
    assert c["severity"] == "high"
    assert "T1046" in c["mitre_techniques"]
    assert "T1110" in c["mitre_techniques"]
    assert conn.alerts[a1_id]["case_id"] == case_id
    assert conn.alerts[a2_id]["case_id"] == case_id


@pytest.mark.asyncio
async def test_end_to_end_case_grouping_and_investigation_report():
    """End-to-End Test: 3 correlated alerts auto-group into 1 Case, and Forensics Engine investigates the Case."""
    from app.forensics.engine import ForensicsEngine

    conn = MockAsyncpgConnection()
    tenant_id = uuid.uuid4()

    # 1. Incoming Alert 1: External Port Scan
    a1_id = uuid.uuid4()
    a1 = {
        "id": str(a1_id),
        "title": "Firewall External Port Scan",
        "severity": "low",
        "affected_hosts": ["inetfw"],
        "src_ip": "192.42.1.174",
        "mitre_techniques": ["T1046"],
        "timestamp": "2026-05-14T08:00:00Z",
    }
    conn.alerts[a1_id] = a1

    # 2. Incoming Alert 2: SSH Brute Force
    a2_id = uuid.uuid4()
    a2 = {
        "id": str(a2_id),
        "title": "SSH Failed Logins (Brute Force)",
        "severity": "medium",
        "affected_hosts": ["inetfw"],
        "src_ip": "192.42.1.174",
        "mitre_techniques": ["T1110", "T1078"],
        "timestamp": "2026-05-14T08:05:00Z",
    }
    conn.alerts[a2_id] = a2

    # 3. Incoming Alert 3: Suricata ELF Malware Download
    a3_id = uuid.uuid4()
    a3 = {
        "id": str(a3_id),
        "title": "Suricata Suspicious ELF Executable Download",
        "severity": "critical",
        "affected_hosts": ["inetfw"],
        "src_ip": "192.42.1.174",
        "mitre_techniques": ["T1105", "T1059.004"],
        "timestamp": "2026-05-14T08:12:00Z",
    }
    conn.alerts[a3_id] = a3

    # Run auto-grouping sequentially as they arrive
    r1 = await auto_group_alert(conn, alert_id=a1_id, tenant_id=tenant_id, raw_alert=a1)
    r2 = await auto_group_alert(conn, alert_id=a2_id, tenant_id=tenant_id, raw_alert=a2)
    r3 = await auto_group_alert(conn, alert_id=a3_id, tenant_id=tenant_id, raw_alert=a3)

    # All 3 alerts MUST belong to the exact same Case container
    case_id = uuid.UUID(r1["case_id"])
    assert r2["case_id"] == str(case_id)
    assert r3["case_id"] == str(case_id)
    assert r1["action"] == "created"
    assert r2["action"] == "grouped"
    assert r3["action"] == "grouped"

    final_case = conn.cases[case_id]
    assert len(final_case["alert_ids"]) == 3
    assert final_case["severity"] == "critical"
    assert "T1046" in final_case["mitre_techniques"]
    assert "T1110" in final_case["mitre_techniques"]
    assert "T1105" in final_case["mitre_techniques"]

    # Now simulate launching an AI Case Investigation on the Case container:
    # Project case alerts into the investigation payload (mirroring /cases/{id}/investigate)
    case_alert_summary = (
        f"Case {final_case['case_number']}: {final_case['title']}\n"
        f"Linked alert [low]: {a1['title']}\n"
        f"Linked alert [medium]: {a2['title']}\n"
        f"Linked alert [critical]: {a3['title']}"
    )
    combined_raw_alert = {
        "title": final_case["title"],
        "severity": final_case["severity"],
        "hostname": "inetfw",
        "src_ip": "192.42.1.174",
        "affected_hosts": ["inetfw"],
        "affected_ips": ["192.42.1.174"],
        "mitre_techniques": final_case["mitre_techniques"],
    }
    simulated_telemetry = [
        {"ts": a1["timestamp"], "host": "inetfw", "ip": "192.42.1.174", "action": "port_scan", "stage": "reconnaissance"},
        {"ts": a2["timestamp"], "host": "inetfw", "ip": "192.42.1.174", "action": "failed_ssh", "stage": "initial-access"},
        {"ts": a3["timestamp"], "host": "inetfw", "ip": "192.42.1.174", "action": "download_elf", "stage": "execution"},
    ]

    # Run Forensics Engine on the Case container
    engine = ForensicsEngine()
    package = engine.analyze(
        events=simulated_telemetry,
        incident_id=str(case_id),
        incident_host="inetfw",
        raw_alert=combined_raw_alert,
    )

    assert package.kill_chain_phases is not None
    assert package.attack_chain is not None
    assert len(package.timeline) >= 3

    # Render final Deterministic Investigation Report
    report = package.markdown_report or engine.report_generator.generate(package)
    assert "# Investigation Report" in report
    assert "inetfw" in report
    assert "Initial Access" in report

