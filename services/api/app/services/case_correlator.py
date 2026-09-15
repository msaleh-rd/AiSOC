"""Automated Case Correlation and Grouping Engine.

Aggregates related alerts into a single Case container based on:
1. Shared attack chain (`chain_id` from Fusion or tags).
2. Entity touch-set overlap (hosts, IPs, users) within a sliding time window (default 2h).
3. Primary entity affiliation.

When a related alert arrives:
- If an active Case exists: automatically attach alert to `case.alert_ids`,
  update `alerts.case_id`, elevate case severity if higher, union MITRE techniques,
  and log an audit comment to `aisoc_case_comments`.
- If no active Case exists: auto-create a new Case container for the alert and entity.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


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
    except Exception as exc:  # noqa: BLE001 - best effort, never fail database transaction
        logger.debug("case_correlator.realtime_notify_failed: %s", exc)


# Severity rank ladder (higher = more severe)
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# Default correlation window for grouping active alerts
DEFAULT_CORRELATION_WINDOW: timedelta = timedelta(hours=2)

# Case statuses considered active for receiving follow-on alerts
ACTIVE_CASE_STATUSES: tuple[str, ...] = ("new", "triaged", "investigating")


class CorrelationAction(str, Enum):
    GROUPED = "grouped"  # Attached to existing active Case
    CREATED = "created"  # New Case created
    IGNORED = "ignored"  # Below threshold or unroutable


@dataclass
class CorrelationResult:
    action: CorrelationAction
    case_id: uuid.UUID | None
    case_number: str | None
    is_new_case: bool
    reason: str
    linked_alert_count: int
    matched_entity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "case_id": str(self.case_id) if self.case_id else None,
            "case_number": self.case_number,
            "is_new_case": self.is_new_case,
            "reason": self.reason,
            "linked_alert_count": self.linked_alert_count,
            "matched_entity": self.matched_entity,
        }


def max_severity(sev_a: str | None, sev_b: str | None) -> str:
    """Return the higher severity between sev_a and sev_b."""
    a = str(sev_a or "low").strip().lower()
    b = str(sev_b or "low").strip().lower()
    rank_a = _SEVERITY_ORDER.get(a, 1)
    rank_b = _SEVERITY_ORDER.get(b, 1)
    return a if rank_a >= rank_b else b


def extract_alert_entities(alert: Any) -> tuple[list[str], list[str], list[str], str | None, list[str]]:
    """Extract (hosts, ips, users, primary_entity, mitre_techniques) from an alert model/dict."""
    hosts: list[str] = []
    ips: list[str] = []
    users: list[str] = []
    mitre: list[str] = []

    def _get(field_name: str, default: Any = None) -> Any:
        if isinstance(alert, dict):
            return alert.get(field_name, default)
        return getattr(alert, field_name, default)

    # Hosts
    for h in _get("affected_hosts") or []:
        if h and str(h) not in hosts:
            hosts.append(str(h))
    raw_host = _get("hostname") or _get("host")
    if raw_host and str(raw_host) not in hosts:
        hosts.append(str(raw_host))

    # IPs
    for ip in _get("affected_ips") or []:
        if ip and str(ip) not in ips:
            ips.append(str(ip))
    src_ip = _get("src_ip") or _get("source_ip")
    if src_ip and str(src_ip) not in ips:
        ips.append(str(src_ip))
    dst_ip = _get("dst_ip") or _get("dest_ip")
    if dst_ip and str(dst_ip) not in ips:
        ips.append(str(dst_ip))

    # Users
    for u in _get("affected_users") or []:
        if u and str(u) not in users:
            users.append(str(u))
    username = _get("username") or _get("user")
    if username and str(username) not in users:
        users.append(str(username))

    # MITRE techniques
    for t in _get("mitre_techniques") or []:
        if isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id")
            if tid and str(tid) not in mitre:
                mitre.append(str(tid))
        elif t and str(t) not in mitre:
            mitre.append(str(t))

    # Determine primary entity string for labeling
    primary_entity: str | None = None
    if hosts:
        primary_entity = f"host:{hosts[0]}"
    elif users:
        primary_entity = f"user:{users[0]}"
    elif ips:
        primary_entity = f"ip:{ips[0]}"

    return hosts, ips, users, primary_entity, mitre


class CaseCorrelator:
    """Core engine for correlating incoming alerts with active Cases."""

    def __init__(self, window: timedelta = DEFAULT_CORRELATION_WINDOW) -> None:
        self.window = window

    async def correlate_alert(
        self,
        db: AsyncSession,
        alert: Any,
        *,
        min_severity_for_new_case: str = "low",
    ) -> CorrelationResult:
        """Correlate an alert with an active Case or auto-create a new Case.

        Args:
            db: Database session.
            alert: Alert instance or dictionary with alert fields.
            min_severity_for_new_case: Minimum severity required to automatically open
                a new case (default 'low').
        """
        def _get(field_name: str, default: Any = None) -> Any:
            if isinstance(alert, dict):
                return alert.get(field_name, default)
            return getattr(alert, field_name, default)

        raw_id = _get("id")
        if not raw_id:
            return CorrelationResult(
                action=CorrelationAction.IGNORED,
                case_id=None,
                case_number=None,
                is_new_case=False,
                reason="Alert missing id",
                linked_alert_count=0,
            )

        alert_id = uuid.UUID(str(raw_id)) if not isinstance(raw_id, uuid.UUID) else raw_id
        raw_tenant = _get("tenant_id")
        tenant_id = uuid.UUID(str(raw_tenant)) if not isinstance(raw_tenant, uuid.UUID) else raw_tenant
        severity = str(_get("severity") or "medium").lower()
        title = str(_get("title") or "Security Alert")

        # Extract entities and chain info
        hosts, ips, users, primary_entity, techniques = extract_alert_entities(alert)

        # Check chain_id from enrichments or tags
        chain_id: str | None = None
        tags = _get("tags") or {}
        if isinstance(tags, dict) and tags.get("chain_id"):
            chain_id = str(tags["chain_id"])
        enrichments = _get("enrichment_data") or {}
        if isinstance(enrichments, dict) and enrichments.get("attack_chain", {}).get("chain_id"):
            chain_id = str(enrichments["attack_chain"]["chain_id"])

        cutoff = datetime.now(UTC) - self.window

        # -------------------------------------------------------------------
        # Step 1: Query for an Active Matching Case
        # -------------------------------------------------------------------
        # Candidate entity identifiers for tag matching
        entity_keys: list[str] = []
        if primary_entity:
            entity_keys.append(primary_entity)
        for h in hosts:
            entity_keys.append(f"host:{h}")
        for u in users:
            entity_keys.append(f"user:{u}")
        for ip in ips:
            entity_keys.append(f"ip:{ip}")

        # Find the best active case:
        # 1. Matches chain_id in tags, OR
        # 2. Matches primary_entity in tags, OR
        # 3. Intersects entity touch-set with an alert already inside the case
        query = text("""
            SELECT c.id, c.case_number, c.title, c.severity, c.status,
                   c.mitre_techniques, c.alert_ids, c.tags
            FROM aisoc_cases c
            WHERE c.tenant_id = :tenant_id
              AND c.status IN ('new', 'triaged', 'investigating')
              AND c.updated_at >= :cutoff
              AND (
                (:chain_id IS NOT NULL AND c.tags->>'chain_id' = :chain_id)
                OR (c.tags->>'primary_entity' = ANY(:entity_keys))
                OR (
                  CARDINALITY(c.alert_ids) > 0 AND EXISTS (
                    SELECT 1 FROM alerts a
                    WHERE a.id = ANY(c.alert_ids)
                      AND a.tenant_id = :tenant_id
                      AND (
                        (CAST(:hosts AS TEXT[]) IS NOT NULL AND a.affected_hosts ?| :hosts)
                        OR (CAST(:ips AS TEXT[]) IS NOT NULL AND a.affected_ips ?| :ips)
                        OR (CAST(:users AS TEXT[]) IS NOT NULL AND a.affected_users ?| :users)
                      )
                  )
                )
              )
            ORDER BY c.updated_at DESC
            LIMIT 1
        """).bindparams(
            tenant_id=tenant_id,
            cutoff=cutoff,
            chain_id=chain_id,
            entity_keys=entity_keys if entity_keys else [""],
            hosts=hosts if hosts else None,
            ips=ips if ips else None,
            users=users if users else None,
        )

        match = (await db.execute(query)).fetchone()

        if match:
            # -------------------------------------------------------------------
            # Step 2: Group into Existing Active Case
            # -------------------------------------------------------------------
            case_id = match.id
            case_number = match.case_number
            existing_alerts: list[uuid.UUID] = list(match.alert_ids or [])
            existing_severity = str(match.severity)
            existing_mitre = list(match.mitre_techniques or []) if isinstance(match.mitre_techniques, list) else []

            # Check if alert is already in the case (idempotent)
            if alert_id in existing_alerts:
                return CorrelationResult(
                    action=CorrelationAction.GROUPED,
                    case_id=case_id,
                    case_number=case_number,
                    is_new_case=False,
                    reason="Alert already present in active case",
                    linked_alert_count=len(existing_alerts),
                    matched_entity=primary_entity,
                )

            # Append alert
            updated_alerts = existing_alerts + [alert_id]
            new_severity = max_severity(existing_severity, severity)

            # Union MITRE techniques
            combined_mitre = list(existing_mitre)
            for t in techniques:
                if t not in combined_mitre:
                    combined_mitre.append(t)

            # Update aisoc_cases
            update_case_sql = text("""
                UPDATE aisoc_cases
                SET alert_ids = array(SELECT DISTINCT unnest(alert_ids || CAST(:new_ids AS UUID[]))),
                    severity = :severity,
                    mitre_techniques = CAST(:mitre AS JSONB),
                    updated_at = now()
                WHERE id = :case_id AND tenant_id = :tenant_id
            """).bindparams(
                new_ids=[str(alert_id)],
                severity=new_severity,
                mitre=json.dumps(combined_mitre),
                case_id=case_id,
                tenant_id=tenant_id,
            )
            await db.execute(update_case_sql)

            # Update alerts.case_id
            update_alert_sql = text("""
                UPDATE alerts
                SET case_id = :case_id,
                    updated_at = now()
                WHERE id = :alert_id AND tenant_id = :tenant_id
            """).bindparams(
                case_id=case_id,
                alert_id=alert_id,
                tenant_id=tenant_id,
            )
            await db.execute(update_alert_sql)

            # Insert system comment
            reason = f"shared entity '{primary_entity}'" if primary_entity else "correlated attack chain"
            comment_body = (
                f"[Auto-Correlation] Linked alert '{title}' ({severity.upper()}) to case via {reason}. "
                f"Container now holds {len(updated_alerts)} linked alert(s)."
            )
            insert_comment_sql = text("""
                INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
                VALUES (gen_random_uuid(), :case_id, :tenant_id, 'system:auto-correlator', :body, TRUE, now())
            """).bindparams(
                case_id=case_id,
                tenant_id=tenant_id,
                body=comment_body,
            )
            await db.execute(insert_comment_sql)

            # Check for severity escalation
            is_escalated = _SEVERITY_ORDER.get(new_severity, 0) > _SEVERITY_ORDER.get(existing_severity, 0)
            if is_escalated:
                escalation_comment = (
                    f"[Severity Escalated] Case severity elevated from {existing_severity.upper()} to {new_severity.upper()} "
                    f"by incoming alert '{title}'."
                )
                insert_escalation_sql = text("""
                    INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
                    VALUES (gen_random_uuid(), :case_id, :tenant_id, 'system:auto-correlator', :body, TRUE, now())
                """).bindparams(
                    case_id=case_id,
                    tenant_id=tenant_id,
                    body=escalation_comment,
                )
                await db.execute(insert_escalation_sql)

            await db.commit()

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
                "case_correlator.grouped_alert",
                alert_id=str(alert_id),
                case_id=str(case_id),
                case_number=case_number,
                total_alerts=len(updated_alerts),
                escalated=is_escalated,
            )

            return CorrelationResult(
                action=CorrelationAction.GROUPED,
                case_id=case_id,
                case_number=case_number,
                is_new_case=False,
                reason=f"Grouped into active case via {reason}",
                linked_alert_count=len(updated_alerts),
                matched_entity=primary_entity,
            )

        # -------------------------------------------------------------------
        # Step 3: No Active Case Match — Auto-Promote to New Case
        # -------------------------------------------------------------------
        # Check if severity meets threshold for auto-creation
        if _SEVERITY_ORDER.get(severity, 1) < _SEVERITY_ORDER.get(min_severity_for_new_case.lower(), 2):
            return CorrelationResult(
                action=CorrelationAction.IGNORED,
                case_id=None,
                case_number=None,
                is_new_case=False,
                reason=f"Alert severity '{severity}' below threshold '{min_severity_for_new_case}' for new case creation",
                linked_alert_count=0,
                matched_entity=primary_entity,
            )

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

        insert_case_sql = text("""
            INSERT INTO aisoc_cases (
                id, tenant_id, case_number, title, description, severity, status,
                mitre_techniques, alert_ids, tags, opened_at, created_at, updated_at, created_by
            ) VALUES (
                :id, :tenant_id, :case_number, :title, :description, :severity, 'new',
                CAST(:mitre AS JSONB), CAST(:alert_ids AS UUID[]), CAST(:tags AS JSONB),
                now(), now(), now(), 'system:auto-correlator'
            )
        """).bindparams(
            id=new_case_id,
            tenant_id=tenant_id,
            case_number=new_case_number,
            title=case_title,
            description=case_description,
            severity=severity,
            mitre=json.dumps(techniques),
            alert_ids=[str(alert_id)],
            tags=json.dumps(case_tags),
        )
        await db.execute(insert_case_sql)

        # Update alerts.case_id
        update_alert_sql = text("""
            UPDATE alerts
            SET case_id = :case_id,
                updated_at = now()
            WHERE id = :alert_id AND tenant_id = :tenant_id
        """).bindparams(
            case_id=new_case_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
        )
        await db.execute(update_alert_sql)

        # Insert initial system comment
        initial_comment = (
            f"[Auto-Correlation] Case created automatically from initial alert '{title}' "
            f"({severity.upper()}) on {primary_entity or 'unassigned entity'}."
        )
        insert_comment_sql = text("""
            INSERT INTO aisoc_case_comments (id, case_id, tenant_id, author, body, is_system, created_at)
            VALUES (gen_random_uuid(), :case_id, :tenant_id, 'system:auto-correlator', :body, TRUE, now())
        """).bindparams(
            case_id=new_case_id,
            tenant_id=tenant_id,
            body=initial_comment,
        )
        await db.execute(insert_comment_sql)
        await db.commit()

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
            "case_correlator.created_case",
            alert_id=str(alert_id),
            case_id=str(new_case_id),
            case_number=new_case_number,
            primary_entity=primary_entity,
        )

        return CorrelationResult(
            action=CorrelationAction.CREATED,
            case_id=new_case_id,
            case_number=new_case_number,
            is_new_case=True,
            reason=f"Created new correlation container for {primary_entity or 'alert'}",
            linked_alert_count=1,
            matched_entity=primary_entity,
        )
