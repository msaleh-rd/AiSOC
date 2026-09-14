"""Asyncpg-native automated Case grouping and promotion worker for agents.

Ensures that alerts processed by the agents worker automatically join an active
Case container (or open a new Case) in PostgreSQL without requiring manual UI intervention.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

DEFAULT_CORRELATION_WINDOW = timedelta(hours=2)


async def notify_case_realtime(
    tenant_id: str | uuid.UUID,
    case_id: str | uuid.UUID,
    case_number: str | None,
    event_type: str,
    severity: str | None = None,
    old_severity: str | None = None,
    title: str | None = None,
    summary: str | None = None,
) -> None:
    """Best-effort async fan-out of case lifecycle events to the realtime service."""
    realtime_url = os.environ.get("REALTIME_URL", "http://localhost:8086")
    internal_token = os.environ.get("INTERNAL_TOKEN", "")
    headers = {"Content-Type": "application/json"}
    if internal_token:
        headers["X-Internal-Token"] = internal_token
    payload = {
        "tenant_id": str(tenant_id),
        "case_id": str(case_id),
        "case_number": case_number,
        "event_type": event_type,
        "severity": severity,
        "old_severity": old_severity,
        "title": title,
        "summary": summary,
    }
    try:
        import httpx

        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{realtime_url}/internal/case-event", headers=headers, json=payload)
    except Exception as exc:  # noqa: BLE001
        logger.debug("case_grouping.realtime_notify_failed: %s", exc)



def max_severity(a: str | None, b: str | None) -> str:
    sa = _SEVERITY_ORDER.get(str(a or "low").strip().lower(), 1)
    sb = _SEVERITY_ORDER.get(str(b or "low").strip().lower(), 1)
    return a if sa >= sb else b


def _extract_entities(raw_alert: dict[str, Any]) -> tuple[list[str], list[str], list[str], str | None, list[str]]:
    hosts: list[str] = []
    ips: list[str] = []
    users: list[str] = []
    mitre: list[str] = []

    # Hosts
    for h in raw_alert.get("affected_hosts") or []:
        if h and str(h) not in hosts:
            hosts.append(str(h))
    raw_host = raw_alert.get("hostname") or raw_alert.get("host")
    if raw_host and str(raw_host) not in hosts:
        hosts.append(str(raw_host))

    # IPs
    for ip in raw_alert.get("affected_ips") or []:
        if ip and str(ip) not in ips:
            ips.append(str(ip))
    for key in ("src_ip", "source_ip", "dst_ip", "dest_ip"):
        val = raw_alert.get(key)
        if val and str(val) not in ips:
            ips.append(str(val))

    # Users
    for u in raw_alert.get("affected_users") or []:
        if u and str(u) not in users:
            users.append(str(u))
    username = raw_alert.get("username") or raw_alert.get("user")
    if username and str(username) not in users:
        users.append(str(username))

    # MITRE techniques
    for t in raw_alert.get("mitre_techniques") or []:
        if isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id")
            if tid and str(tid) not in mitre:
                mitre.append(str(tid))
        elif t and str(t) not in mitre:
            mitre.append(str(t))

    primary_entity: str | None = None
    if hosts:
        primary_entity = f"host:{hosts[0]}"
    elif users:
        primary_entity = f"user:{users[0]}"
    elif ips:
        primary_entity = f"ip:{ips[0]}"

    return hosts, ips, users, primary_entity, mitre


async def auto_group_alert(
    conn: asyncpg.Connection,
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    raw_alert: dict[str, Any],
    verdict: str | None = None,
    window: timedelta = DEFAULT_CORRELATION_WINDOW,
    min_severity_for_new_case: str = "low",
) -> dict[str, Any]:
    """Correlate an alert into an active Case container or create a new Case."""
    title = str(raw_alert.get("title") or "Security Alert")
    severity = str(raw_alert.get("severity") or "medium").lower()

    hosts, ips, users, primary_entity, techniques = _extract_entities(raw_alert)

    # Chain ID
    chain_id = None
    tags = raw_alert.get("tags") or {}
    if isinstance(tags, dict) and tags.get("chain_id"):
        chain_id = str(tags["chain_id"])
    enrichments = raw_alert.get("enrichment_data") or {}
    if isinstance(enrichments, dict) and enrichments.get("attack_chain", {}).get("chain_id"):
        chain_id = str(enrichments["attack_chain"]["chain_id"])

    cutoff = datetime.now(UTC) - window

    entity_keys: list[str] = []
    if primary_entity:
        entity_keys.append(primary_entity)
    for h in hosts:
        entity_keys.append(f"host:{h}")
    for u in users:
        entity_keys.append(f"user:{u}")
    for ip in ips:
        entity_keys.append(f"ip:{ip}")

    # 1. Search for active case
    row = await conn.fetchrow(
        """
        SELECT c.id, c.case_number, c.severity, c.status, c.mitre_techniques, c.alert_ids, c.tags
        FROM aisoc_cases c
        WHERE c.tenant_id = $1
          AND c.status IN ('new', 'triaged', 'investigating')
          AND c.updated_at >= $2
          AND (
            ($3::text IS NOT NULL AND c.tags->>'chain_id' = $3)
            OR (c.tags->>'primary_entity' = ANY($4::text[]))
            OR (
              CARDINALITY(c.alert_ids) > 0 AND EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.id = ANY(c.alert_ids)
                  AND a.tenant_id = $1
                  AND (
                    ($5::text[] IS NOT NULL AND a.affected_hosts ?| $5)
                    OR ($6::text[] IS NOT NULL AND a.affected_ips ?| $6)
                    OR ($7::text[] IS NOT NULL AND a.affected_users ?| $7)
                  )
              )
            )
          )
        ORDER BY c.updated_at DESC
        LIMIT 1
        """,
        tenant_id,
        cutoff,
        chain_id,
        entity_keys or [""],
        hosts or None,
        ips or None,
        users or None,
    )

    if row:
        case_id = row["id"]
        case_number = row["case_number"]
        existing_alerts = list(row["alert_ids"] or [])
        existing_severity = str(row["severity"])

        raw_mitre = row["mitre_techniques"]
        existing_mitre = (
            json.loads(raw_mitre) if isinstance(raw_mitre, str)
            else list(raw_mitre or [])
        )

        if alert_id in existing_alerts:
            return {
                "action": "grouped",
                "case_id": str(case_id),
                "case_number": case_number,
                "is_new_case": False,
                "linked_alert_count": len(existing_alerts),
            }

        new_severity = max_severity(existing_severity, severity)
        combined_mitre = list(existing_mitre)
        for t in techniques:
            if t not in combined_mitre:
                combined_mitre.append(t)

        updated_alerts = existing_alerts + [alert_id]

        # Update case
        await conn.execute(
            """
            UPDATE aisoc_cases
            SET alert_ids = array(SELECT DISTINCT unnest(alert_ids || $1::uuid[])),
                severity = $2,
                mitre_techniques = $3::jsonb,
                updated_at = now()
            WHERE id = $4 AND tenant_id = $5
            """,
            [alert_id],
            new_severity,
            json.dumps(combined_mitre),
            case_id,
            tenant_id,
        )

        # Update alert
        await conn.execute(
            """
            UPDATE alerts
            SET case_id = $1, updated_at = now()
            WHERE id = $2 AND tenant_id = $3
            """,
            case_id,
            alert_id,
            tenant_id,
        )

        # Comment
        reason = f"shared entity '{primary_entity}'" if primary_entity else "correlated attack chain"
        comment = (
            f"[Auto-Correlation] Linked alert '{title}' ({severity.upper()}) to case via {reason}. "
            f"Container now holds {len(updated_alerts)} linked alert(s)."
        )
        await conn.execute(
            """
            INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
            VALUES (uuid_generate_v4(), $1, $2, 'system:auto-correlator', $3, TRUE, now())
            """,
            case_id,
            tenant_id,
            comment,
        )

        # Check for severity escalation
        is_escalated = _SEVERITY_ORDER.get(new_severity, 0) > _SEVERITY_ORDER.get(existing_severity, 0)
        if is_escalated:
            escalation_comment = (
                f"[Severity Escalated] Case severity elevated from {existing_severity.upper()} to {new_severity.upper()} "
                f"by incoming alert '{title}'."
            )
            await conn.execute(
                """
                INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
                VALUES (uuid_generate_v4(), $1, $2, 'system:auto-correlator', $3, TRUE, now())
                """,
                case_id,
                tenant_id,
                escalation_comment,
            )

        # Realtime fan-out
        await notify_case_realtime(
            tenant_id=tenant_id,
            case_id=case_id,
            case_number=case_number,
            event_type="escalation" if is_escalated else "grouped",
            severity=new_severity,
            old_severity=existing_severity if is_escalated else None,
            title=title,
            summary=f"Case severity elevated to {new_severity.upper()} by alert '{title}'." if is_escalated else None,
        )

        logger.info(
            "auto_group_alert.grouped",
            alert_id=str(alert_id),
            case_id=str(case_id),
            case_number=case_number,
            alerts_count=len(updated_alerts),
            escalated=is_escalated,
        )

        return {
            "action": "grouped",
            "case_id": str(case_id),
            "case_number": case_number,
            "is_new_case": False,
            "linked_alert_count": len(updated_alerts),
        }

    # 2. No active case — check if eligible to create
    if _SEVERITY_ORDER.get(severity, 1) < _SEVERITY_ORDER.get(min_severity_for_new_case.lower(), 2):
        return {
            "action": "ignored",
            "case_id": None,
            "case_number": None,
            "is_new_case": False,
            "reason": f"Severity '{severity}' below threshold",
        }

    new_case_id = uuid.uuid4()
    new_case_number = f"CASE-{new_case_id.hex[:8].upper()}"
    case_title = f"Incident on {primary_entity}: {title}" if primary_entity else f"Incident: {title}"
    case_description = (
        f"Automated correlation container opened for {primary_entity or 'detection'}.\n\n"
        f"Initial Alert: {title} ({severity.upper()})\n"
        f"MITRE ATT&CK: {', '.join(techniques) if techniques else 'None specified'}"
    )
    case_tags = {
        "auto_created": True,
        "primary_entity": primary_entity,
        "chain_id": chain_id,
    }

    await conn.execute(
        """
        INSERT INTO aisoc_cases (
            id, tenant_id, case_number, title, description, severity, status,
            mitre_techniques, alert_ids, tags, opened_at, created_at, updated_at, created_by
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'new',
            $7::jsonb, $8::uuid[], $9::jsonb,
            now(), now(), now(), 'system:auto-correlator'
        )
        """,
        new_case_id,
        tenant_id,
        new_case_number,
        case_title,
        case_description,
        severity,
        json.dumps(techniques),
        [alert_id],
        json.dumps(case_tags),
    )

    # Update alert
    await conn.execute(
        """
        UPDATE alerts
        SET case_id = $1, updated_at = now()
        WHERE id = $2 AND tenant_id = $3
        """,
        new_case_id,
        alert_id,
        tenant_id,
    )

    # Comment
    initial_comment = (
        f"[Auto-Correlation] Case created automatically from initial alert '{title}' "
        f"({severity.upper()}) on {primary_entity or 'unassigned entity'}."
    )
    await conn.execute(
        """
        INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
        VALUES (uuid_generate_v4(), $1, $2, 'system:auto-correlator', $3, TRUE, now())
        """,
        new_case_id,
        tenant_id,
        initial_comment,
    )

    # Realtime fan-out
    await notify_case_realtime(
        tenant_id=tenant_id,
        case_id=new_case_id,
        case_number=new_case_number,
        event_type="created",
        severity=severity,
        title=case_title,
        summary=f"New case auto-created from alert '{title}' on {primary_entity or 'unassigned entity'}.",
    )

    logger.info(
        "auto_group_alert.created",
        alert_id=str(alert_id),
        case_id=str(new_case_id),
        case_number=new_case_number,
        primary_entity=primary_entity,
    )

    return {
        "action": "created",
        "case_id": str(new_case_id),
        "case_number": new_case_number,
        "is_new_case": True,
        "linked_alert_count": 1,
    }
