"""Tests for Automated Case Correlation and Grouping Engine (CaseCorrelator).

Validates:
1. Two alerts on the same host auto-group into 1 Case container.
2. Two alerts on distinct hosts create distinct Cases.
3. Severity escalation: adding a High/Critical alert elevates a Medium Case.
4. MITRE ATT&CK techniques union across grouped alerts without duplicates.
5. Rolling window expiration: an alert after the window cutoff opens a new Case.
6. Tenant isolation: Tenant A's alerts cannot match or group into Tenant B's cases.
7. Bi-directional link: `alerts.case_id` is updated when grouped.
8. API endpoints:
   - `GET /cases/{case_id}/alerts`
   - `POST /cases/auto-correlate`
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.case_correlator import (
    CaseCorrelator,
    CorrelationAction,
    extract_alert_entities,
    max_severity,
)


# ────────────────────────────────────────────────────────────────────────────
# Unit Tests for Helper Functions
# ────────────────────────────────────────────────────────────────────────────


def test_max_severity():
    assert max_severity("low", "high") == "high"
    assert max_severity("high", "low") == "high"
    assert max_severity("medium", "critical") == "critical"
    assert max_severity("critical", "high") == "critical"
    assert max_severity("info", "low") == "low"
    assert max_severity("medium", "medium") == "medium"
    assert max_severity(None, "high") == "high"


def test_extract_alert_entities():
    alert = {
        "hostname": "inetfw",
        "affected_hosts": ["inetfw", "WIN-DC01"],
        "src_ip": "192.42.1.174",
        "affected_ips": ["192.42.1.174", "10.0.0.5"],
        "username": "aecid",
        "affected_users": ["aecid"],
        "mitre_techniques": ["T1078", "T1059.001"],
    }
    hosts, ips, users, primary_entity, mitre = extract_alert_entities(alert)
    assert hosts == ["inetfw", "WIN-DC01"]
    assert ips == ["192.42.1.174", "10.0.0.5"]
    assert users == ["aecid"]
    assert primary_entity == "host:inetfw"
    assert mitre == ["T1078", "T1059.001"]


# ────────────────────────────────────────────────────────────────────────────
# Mock Database Session for Correlation Engine
# ────────────────────────────────────────────────────────────────────────────


class MockAsyncSession:
    """In-memory simulated database session for CaseCorrelator."""

    def __init__(self):
        self.cases: dict[uuid.UUID, dict[str, Any]] = {}
        self.alerts: dict[uuid.UUID, dict[str, Any]] = {}
        self.comments: list[dict[str, Any]] = []

    async def execute(self, statement: Any):
        sql = str(getattr(statement, "text", statement)).strip()
        params = getattr(statement, "_bindparams", {})
        # Flatten bind params
        param_dict = {}
        for k, v in params.items():
            param_dict[k] = getattr(v, "value", v)

        # 1. Active case search query
        if "SELECT c.id, c.case_number" in sql:
            tenant_id = param_dict.get("tenant_id")
            chain_id = param_dict.get("chain_id")
            entity_keys = param_dict.get("entity_keys") or []
            cutoff = param_dict.get("cutoff")
            hosts = param_dict.get("hosts") or []
            ips = param_dict.get("ips") or []
            users = param_dict.get("users") or []

            matching_case = None
            # Find newest active case matching criteria
            sorted_cases = sorted(
                self.cases.values(),
                key=lambda c: c["updated_at"],
                reverse=True,
            )
            for c in sorted_cases:
                if c["tenant_id"] != tenant_id:
                    continue
                if c["status"] not in ("new", "triaged", "investigating"):
                    continue
                if cutoff and c["updated_at"] < cutoff:
                    continue

                # Match chain_id
                c_tags = c.get("tags") or {}
                if chain_id and c_tags.get("chain_id") == chain_id:
                    matching_case = c
                    break

                # Match primary entity in tags
                if c_tags.get("primary_entity") in entity_keys:
                    matching_case = c
                    break

                # Match shared alert entities
                has_entity_overlap = False
                for aid in c.get("alert_ids", []):
                    linked_alert = self.alerts.get(aid)
                    if linked_alert:
                        if any(h in (linked_alert.get("affected_hosts") or []) for h in hosts):
                            has_entity_overlap = True
                            break
                        if any(i in (linked_alert.get("affected_ips") or []) for i in ips):
                            has_entity_overlap = True
                            break
                        if any(u in (linked_alert.get("affected_users") or []) for u in users):
                            has_entity_overlap = True
                            break
                if has_entity_overlap:
                    matching_case = c
                    break

            mock_result = MagicMock()
            if matching_case:
                row = MagicMock()
                for k, v in matching_case.items():
                    setattr(row, k, v)
                mock_result.fetchone.return_value = row
            else:
                mock_result.fetchone.return_value = None
            return mock_result

        # 2. Update aisoc_cases
        elif "UPDATE aisoc_cases" in sql:
            case_id = param_dict.get("case_id")
            if case_id in self.cases:
                new_ids = [uuid.UUID(str(x)) for x in (param_dict.get("new_ids") or [])]
                existing = self.cases[case_id].get("alert_ids") or []
                for nid in new_ids:
                    if nid not in existing:
                        existing.append(nid)
                self.cases[case_id]["alert_ids"] = existing
                if "severity" in param_dict:
                    self.cases[case_id]["severity"] = param_dict["severity"]
                if "mitre" in param_dict:
                    self.cases[case_id]["mitre_techniques"] = json.loads(param_dict["mitre"])
                self.cases[case_id]["updated_at"] = datetime.now(UTC)
            mock_result = MagicMock()
            return mock_result

        # 3. Update alerts.case_id
        elif "UPDATE alerts" in sql:
            case_id = param_dict.get("case_id")
            alert_id = param_dict.get("alert_id")
            if alert_id in self.alerts:
                self.alerts[alert_id]["case_id"] = case_id
                self.alerts[alert_id]["updated_at"] = datetime.now(UTC)
            mock_result = MagicMock()
            return mock_result

        # 4. Insert into aisoc_cases
        elif "INSERT INTO aisoc_cases" in sql:
            new_id = param_dict.get("id")
            self.cases[new_id] = {
                "id": new_id,
                "tenant_id": param_dict.get("tenant_id"),
                "case_number": param_dict.get("case_number"),
                "title": param_dict.get("title"),
                "description": param_dict.get("description"),
                "severity": param_dict.get("severity"),
                "status": "new",
                "alert_ids": [uuid.UUID(str(x)) for x in (param_dict.get("alert_ids") or [])],
                "mitre_techniques": json.loads(param_dict.get("mitre") or "[]"),
                "tags": json.loads(param_dict.get("tags") or "{}"),
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
            mock_result = MagicMock()
            return mock_result

        # 5. Insert comment
        elif "INSERT INTO aisoc_case_comments" in sql:
            self.comments.append(param_dict)
            mock_result = MagicMock()
            return mock_result

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        mock_result.fetchall.return_value = []
        return mock_result

    async def commit(self):
        pass

    async def rollback(self):
        pass


# ────────────────────────────────────────────────────────────────────────────
# Core Engine Tests
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_two_alerts_same_host_group_into_single_case():
    """Prove that 1 firewall port scan + 1 SSH brute force on host 'inetfw' group into 1 Case."""
    session = MockAsyncSession()
    correlator = CaseCorrelator(window=timedelta(hours=2))
    tenant_id = uuid.uuid4()

    # Alert 1: Firewall port scan
    alert_1_id = uuid.uuid4()
    alert_1 = {
        "id": alert_1_id,
        "tenant_id": tenant_id,
        "title": "Firewall External Port Scan",
        "severity": "medium",
        "affected_hosts": ["inetfw"],
        "src_ip": "192.42.1.174",
        "mitre_techniques": ["T1046"],
        "event_time": datetime.now(UTC),
    }
    session.alerts[alert_1_id] = dict(alert_1)

    res_1 = await correlator.correlate_alert(session, alert_1)
    assert res_1.action == CorrelationAction.CREATED
    assert res_1.is_new_case is True
    assert res_1.linked_alert_count == 1
    assert res_1.case_id is not None
    case_id = res_1.case_id

    # Alert 2: SSH Brute Force on the same host
    alert_2_id = uuid.uuid4()
    alert_2 = {
        "id": alert_2_id,
        "tenant_id": tenant_id,
        "title": "SSH Failed Logins (Brute Force)",
        "severity": "high",
        "affected_hosts": ["inetfw"],
        "src_ip": "192.42.1.174",
        "mitre_techniques": ["T1110"],
        "event_time": datetime.now(UTC) + timedelta(minutes=5),
    }
    session.alerts[alert_2_id] = dict(alert_2)

    res_2 = await correlator.correlate_alert(session, alert_2)
    assert res_2.action == CorrelationAction.GROUPED
    assert res_2.is_new_case is False
    assert res_2.case_id == case_id
    assert res_2.linked_alert_count == 2

    # Assert Case state in DB
    stored_case = session.cases[case_id]
    assert alert_1_id in stored_case["alert_ids"]
    assert alert_2_id in stored_case["alert_ids"]
    assert len(stored_case["alert_ids"]) == 2
    # Severity bumped from medium to high
    assert stored_case["severity"] == "high"
    # MITRE techniques merged
    assert "T1046" in stored_case["mitre_techniques"]
    assert "T1110" in stored_case["mitre_techniques"]

    # Assert bi-directional alert.case_id linking
    assert session.alerts[alert_1_id]["case_id"] == case_id
    assert session.alerts[alert_2_id]["case_id"] == case_id

    # Assert audit comments written (initial create + linked alert + severity escalation)
    assert len(session.comments) == 3
    assert "Linked alert" in session.comments[1]["body"]
    assert "Severity Escalated" in session.comments[2]["body"]
    assert "MEDIUM to HIGH" in session.comments[2]["body"]


@pytest.mark.asyncio
async def test_three_alerts_full_attack_chain():
    """Prove that Port Scan + SSH + ELF Download all collapse into 1 Case."""
    session = MockAsyncSession()
    correlator = CaseCorrelator()
    tenant_id = uuid.uuid4()

    a1_id, a2_id, a3_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    a1 = {"id": a1_id, "tenant_id": tenant_id, "title": "Port Scan", "severity": "low", "affected_hosts": ["inetfw"], "mitre_techniques": ["T1046"]}
    a2 = {"id": a2_id, "tenant_id": tenant_id, "title": "SSH Brute Force", "severity": "medium", "affected_hosts": ["inetfw"], "mitre_techniques": ["T1110"]}
    a3 = {"id": a3_id, "tenant_id": tenant_id, "title": "ELF Malware Download", "severity": "critical", "affected_hosts": ["inetfw"], "mitre_techniques": ["T1105"]}

    for a in (a1, a2, a3):
        session.alerts[a["id"]] = dict(a)

    r1 = await correlator.correlate_alert(session, a1)
    r2 = await correlator.correlate_alert(session, a2)
    r3 = await correlator.correlate_alert(session, a3)

    assert r1.action == CorrelationAction.CREATED
    assert r2.action == CorrelationAction.GROUPED
    assert r3.action == CorrelationAction.GROUPED
    assert r1.case_id == r2.case_id == r3.case_id

    final_case = session.cases[r1.case_id]
    assert len(final_case["alert_ids"]) == 3
    assert final_case["severity"] == "critical"
    assert set(final_case["mitre_techniques"]) == {"T1046", "T1110", "T1105"}


@pytest.mark.asyncio
async def test_different_hosts_create_distinct_cases():
    """Prove that alerts on different unrelated hosts do NOT group into the same Case."""
    session = MockAsyncSession()
    correlator = CaseCorrelator()
    tenant_id = uuid.uuid4()

    a1 = {"id": uuid.uuid4(), "tenant_id": tenant_id, "title": "Alert Host A", "severity": "high", "affected_hosts": ["server-alpha"]}
    a2 = {"id": uuid.uuid4(), "tenant_id": tenant_id, "title": "Alert Host B", "severity": "high", "affected_hosts": ["server-bravo"]}

    session.alerts[a1["id"]] = dict(a1)
    session.alerts[a2["id"]] = dict(a2)

    r1 = await correlator.correlate_alert(session, a1)
    r2 = await correlator.correlate_alert(session, a2)

    assert r1.action == CorrelationAction.CREATED
    assert r2.action == CorrelationAction.CREATED
    assert r1.case_id != r2.case_id
    assert len(session.cases) == 2


@pytest.mark.asyncio
async def test_tenant_isolation_never_merges_cross_tenant():
    """Prove that Tenant A's alert cannot attach to Tenant B's case even with identical host."""
    session = MockAsyncSession()
    correlator = CaseCorrelator()

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    a1 = {"id": uuid.uuid4(), "tenant_id": tenant_a, "title": "Alert Tenant A", "severity": "high", "affected_hosts": ["shared-name"]}
    a2 = {"id": uuid.uuid4(), "tenant_id": tenant_b, "title": "Alert Tenant B", "severity": "high", "affected_hosts": ["shared-name"]}

    session.alerts[a1["id"]] = dict(a1)
    session.alerts[a2["id"]] = dict(a2)

    r1 = await correlator.correlate_alert(session, a1)
    r2 = await correlator.correlate_alert(session, a2)

    assert r1.action == CorrelationAction.CREATED
    assert r2.action == CorrelationAction.CREATED
    assert r1.case_id != r2.case_id
    assert session.cases[r1.case_id]["tenant_id"] == tenant_a
    assert session.cases[r2.case_id]["tenant_id"] == tenant_b


@pytest.mark.asyncio
async def test_window_expiration_creates_new_case():
    """Prove that an alert arriving after the 2-hour correlation window cutoff opens a new Case."""
    session = MockAsyncSession()
    correlator = CaseCorrelator(window=timedelta(hours=2))
    tenant_id = uuid.uuid4()

    a1 = {"id": uuid.uuid4(), "tenant_id": tenant_id, "title": "Alert 1", "severity": "high", "affected_hosts": ["inetfw"]}
    session.alerts[a1["id"]] = dict(a1)
    r1 = await correlator.correlate_alert(session, a1)

    # Manually age the case to 3 hours ago
    session.cases[r1.case_id]["updated_at"] = datetime.now(UTC) - timedelta(hours=3)

    a2 = {"id": uuid.uuid4(), "tenant_id": tenant_id, "title": "Alert 2 (Late)", "severity": "high", "affected_hosts": ["inetfw"]}
    session.alerts[a2["id"]] = dict(a2)
    r2 = await correlator.correlate_alert(session, a2)

    assert r2.action == CorrelationAction.CREATED
    assert r2.case_id != r1.case_id
    assert len(session.cases) == 2


@pytest.mark.asyncio
async def test_idempotent_alert_submission():
    """Submitting the exact same alert twice returns GROUPED without duplicating IDs."""
    session = MockAsyncSession()
    correlator = CaseCorrelator()
    tenant_id = uuid.uuid4()

    a1 = {"id": uuid.uuid4(), "tenant_id": tenant_id, "title": "Alert", "severity": "high", "affected_hosts": ["inetfw"]}
    session.alerts[a1["id"]] = dict(a1)

    r1 = await correlator.correlate_alert(session, a1)
    r2 = await correlator.correlate_alert(session, a1)

    assert r1.action == CorrelationAction.CREATED
    assert r2.action == CorrelationAction.GROUPED
    assert r2.is_new_case is False
    assert r2.case_id == r1.case_id
    assert len(session.cases[r1.case_id]["alert_ids"]) == 1


# ────────────────────────────────────────────────────────────────────────────
# Endpoint Tests for Cases API
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_case_alerts_endpoint():
    """Verify GET /cases/{case_id}/alerts returns the full alert records."""
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import get_case_alerts

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")
    cid = uuid.uuid4()
    aid = uuid.uuid4()

    db = AsyncMock()
    case_row = MagicMock()
    case_row.id = cid
    case_row.alert_ids = [aid]

    alert_row = {
        "id": aid,
        "tenant_id": tenant_id,
        "title": "Port Scan",
        "description": "Port scan desc",
        "severity": "medium",
        "status": "new",
        "priority": 50,
        "category": "network",
        "mitre_tactics": ["reconnaissance"],
        "mitre_techniques": ["T1046"],
        "connector_type": "suricata",
        "ai_score": 0.8,
        "ai_summary": "Suspicious scan",
        "ai_recommendations": [],
        "confidence": 85,
        "confidence_label": "high",
        "confidence_rationale": [],
        "disposition": None,
        "affected_ips": ["192.42.1.174"],
        "affected_hosts": ["inetfw"],
        "affected_users": [],
        "case_id": cid,
        "tags": [],
        "event_time": datetime.now(UTC),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    async def mock_execute(stmt):
        sql = str(getattr(stmt, "text", stmt)).strip()
        mock_res = MagicMock()
        if "SELECT alert_ids FROM aisoc_cases" in sql:
            mock_res.fetchone.return_value = case_row
        elif "SELECT id, tenant_id, title" in sql:
            mappings_mock = MagicMock()
            mappings_mock.all.return_value = [alert_row]
            mock_res.mappings.return_value = mappings_mock
        return mock_res

    db.execute = mock_execute

    res = await get_case_alerts(case_id=str(cid), db=db, user=user)
    assert res["total"] == 1
    assert len(res["alerts"]) == 1
    assert res["alerts"][0]["title"] == "Port Scan"
    assert res["alerts"][0]["case_id"] == cid


@pytest.mark.asyncio
async def test_auto_correlate_alerts_endpoint():
    """Verify POST /cases/auto-correlate sweeps alerts and correlates them into Cases."""
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import AutoCorrelateRequest, auto_correlate_alerts

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")

    aid = uuid.uuid4()
    alert_row = {
        "id": aid,
        "tenant_id": tenant_id,
        "title": "Port Scan",
        "description": "Port scan desc",
        "severity": "medium",
        "status": "new",
        "mitre_tactics": ["reconnaissance"],
        "mitre_techniques": ["T1046"],
        "affected_ips": ["192.42.1.174"],
        "affected_hosts": ["inetfw"],
        "affected_users": [],
        "case_id": None,
        "tags": {},
        "enrichment_data": {},
        "event_time": datetime.now(UTC),
    }

    session = MockAsyncSession()
    session.alerts[aid] = alert_row

    orig_execute = session.execute

    async def mock_exec(stmt):
        sql = str(getattr(stmt, "text", stmt)).strip()
        if "FROM alerts" in sql and "aisoc_cases" not in sql:
            mappings_mock = MagicMock()
            mappings_mock.all.return_value = [alert_row]
            mock_res = MagicMock()
            mock_res.mappings.return_value = mappings_mock
            return mock_res
        return await orig_execute(stmt)

    session.execute = mock_exec

    req = AutoCorrelateRequest(alert_ids=[aid])
    res = await auto_correlate_alerts(body=req, db=session, user=user)

    assert res.correlated_count == 1
    assert res.cases_created == 1
    assert res.cases_grouped == 0
    assert len(res.results) == 1
    assert res.results[0]["action"] == "created"
    assert res.results[0]["case_id"] is not None


@pytest.mark.asyncio
async def test_case_stats_endpoint():
    """Verify GET /cases/stats returns aggregate correlation metrics."""
    from unittest.mock import AsyncMock
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import case_stats

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")

    stats_row = MagicMock(
        total=10,
        auto_correlated=7,
        manual=3,
        avg_alerts_per_case=3.5,
        critical=2,
        high=3,
        medium=4,
        low=1,
        info=0,
        active=6,
        resolved=4,
    )
    db = MagicMock()
    mock_res = MagicMock()
    mock_res.fetchone.return_value = stats_row
    db.execute = AsyncMock(return_value=mock_res)

    res = await case_stats(db=db, user=user)
    assert res["total"] == 10
    assert res["auto_correlated"] == 7
    assert res["manual"] == 3
    assert res["avg_alerts_per_case"] == 3.5
    assert res["by_severity"]["critical"] == 2
    assert res["by_status"]["active"] == 6


@pytest.mark.asyncio
async def test_re_correlate_orphan_alerts_endpoint():
    """Verify POST /cases/re-correlate sweeps orphan alerts."""
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import re_correlate_orphan_alerts

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")

    aid = uuid.uuid4()
    alert_row = {
        "id": aid,
        "tenant_id": tenant_id,
        "title": "Orphan Port Scan",
        "description": "Port scan desc",
        "severity": "medium",
        "status": "new",
        "mitre_tactics": ["reconnaissance"],
        "mitre_techniques": ["T1046"],
        "affected_ips": ["192.42.1.174"],
        "affected_hosts": ["inetfw"],
        "affected_users": [],
        "case_id": None,
        "tags": {},
        "enrichment_data": {},
        "event_time": datetime.now(UTC),
    }

    session = MockAsyncSession()
    session.alerts[aid] = alert_row

    orig_execute = session.execute

    async def mock_exec(stmt):
        sql = str(getattr(stmt, "text", stmt)).strip()
        if "FROM alerts" in sql and "case_id IS NULL" in sql:
            mappings_mock = MagicMock()
            mappings_mock.all.return_value = [alert_row]
            mock_res = MagicMock()
            mock_res.mappings.return_value = mappings_mock
            return mock_res
        return await orig_execute(stmt)

    session.execute = mock_exec

    res = await re_correlate_orphan_alerts(db=session, user=user, window_hours=24)
    assert res["orphan_count"] == 1
    assert res["correlated_count"] == 1
    assert res["cases_created"] == 1


@pytest.mark.asyncio
async def test_merge_case_endpoint():
    """Verify POST /cases/{target_id}/merge merges source case into target."""
    from unittest.mock import AsyncMock
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import MergeCaseRequest, merge_case

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")

    target_id = uuid.uuid4()
    source_id = uuid.uuid4()
    a1_id, a2_id = uuid.uuid4(), uuid.uuid4()

    target_row = MagicMock(
        id=target_id,
        case_number="CASE-TARGET",
        title="Target Case",
        description="Target desc",
        severity="medium",
        status="new",
        assignee=None,
        mitre_techniques=["T1046"],
        alert_ids=[a1_id],
        observable_graph={},
        evidence_chain=[],
        compliance_frameworks=[],
        opened_at=datetime.now(UTC),
        triaged_at=None,
        resolved_at=None,
        closed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="analyst",
        tags={"auto_created": True},
        sla_due_at=None,
    )

    source_row = MagicMock(
        id=source_id,
        case_number="CASE-SOURCE",
        title="Source Case",
        description="Source desc",
        severity="critical",
        status="new",
        assignee=None,
        mitre_techniques=["T1110"],
        alert_ids=[a2_id],
        observable_graph={},
        evidence_chain=[],
        compliance_frameworks=[],
        opened_at=datetime.now(UTC),
        triaged_at=None,
        resolved_at=None,
        closed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="analyst",
        tags={"auto_created": True},
        sla_due_at=None,
    )

    updated_target = MagicMock(
        id=target_id,
        case_number="CASE-TARGET",
        title="Target Case",
        description="Target desc",
        severity="critical",
        status="new",
        assignee=None,
        mitre_techniques=["T1046", "T1110"],
        alert_ids=[a1_id, a2_id],
        observable_graph={},
        evidence_chain=[],
        compliance_frameworks=[],
        opened_at=datetime.now(UTC),
        triaged_at=None,
        resolved_at=None,
        closed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="analyst",
        tags={"auto_created": True},
        sla_due_at=None,
    )

    db = MagicMock()
    executed_statements = []

    async def mock_exec(stmt):
        sql = str(getattr(stmt, "text", stmt)).strip()
        executed_statements.append(sql)
        mock_res = MagicMock()
        if "SELECT * FROM aisoc_cases WHERE id = :id" in sql or "id = :id" in sql:
            params = getattr(stmt, "_bindparams", {})
            param_dict = {k: getattr(v, "value", v) for k, v in params.items()}
            req_id = param_dict.get("id")
            if req_id == target_id:
                if any("UPDATE aisoc_cases" in s for s in executed_statements):
                    mock_res.fetchone.return_value = updated_target
                else:
                    mock_res.fetchone.return_value = target_row
            elif req_id == source_id:
                mock_res.fetchone.return_value = source_row
        return mock_res

    db.execute = mock_exec
    db.commit = AsyncMock()

    body = MergeCaseRequest(source_case_id=str(source_id))
    merged = await merge_case(case_id=str(target_id), body=body, db=db, user=user)

    assert merged.id == target_id
    assert merged.severity == "critical"
    assert len(merged.alert_ids) == 2


@pytest.mark.asyncio
async def test_split_case_endpoint():
    """Verify POST /cases/{source_id}/split extracts alerts into a new Case."""
    from unittest.mock import AsyncMock
    from app.api.v1.deps import CurrentUser
    from app.api.v1.endpoints.cases import SplitCaseRequest, split_case

    tenant_id = uuid.uuid4()
    user = CurrentUser(user_id=uuid.uuid4(), tenant_id=tenant_id, role="analyst", email="analyst@example.com")

    source_id = uuid.uuid4()
    a1_id, a2_id = uuid.uuid4(), uuid.uuid4()

    source_row = MagicMock(
        id=source_id,
        case_number="CASE-ORIG",
        title="Original Big Incident",
        description="Original desc",
        severity="high",
        status="new",
        assignee=None,
        mitre_techniques=["T1046", "T1110"],
        alert_ids=[a1_id, a2_id],
        observable_graph={},
        evidence_chain=[],
        compliance_frameworks=[],
        opened_at=datetime.now(UTC),
        triaged_at=None,
        resolved_at=None,
        closed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="analyst",
        tags={"auto_created": True},
        sla_due_at=None,
    )

    new_case_id = uuid.uuid4()
    split_result_row = MagicMock(
        id=new_case_id,
        case_number="CASE-SPLIT1",
        title="Split Case",
        description="Split desc",
        severity="high",
        status="new",
        assignee=None,
        mitre_techniques=["T1046", "T1110"],
        alert_ids=[a2_id],
        observable_graph={},
        evidence_chain=[],
        compliance_frameworks=[],
        opened_at=datetime.now(UTC),
        triaged_at=None,
        resolved_at=None,
        closed_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="system:case-split",
        tags={"split_from": str(source_id)},
        sla_due_at=None,
    )

    db = MagicMock()

    async def mock_exec(stmt):
        sql = str(getattr(stmt, "text", stmt)).strip()
        mock_res = MagicMock()
        if "WHERE id = :id" in sql:
            params = getattr(stmt, "_bindparams", {})
            param_dict = {k: getattr(v, "value", v) for k, v in params.items()}
            req_id = param_dict.get("id")
            if req_id == source_id:
                mock_res.fetchone.return_value = source_row
            else:
                mock_res.fetchone.return_value = split_result_row
        return mock_res

    db.execute = mock_exec
    db.commit = AsyncMock()

    body = SplitCaseRequest(alert_ids=[a2_id], title="Split Case")
    res = await split_case(case_id=str(source_id), body=body, db=db, user=user)

    assert res.title == "Split Case"
    assert res.created_by == "system:case-split"
    assert a2_id in res.alert_ids



