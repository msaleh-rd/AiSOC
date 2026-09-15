"""Platform evidence — related alerts from AiSOC's own Postgres alert store.

The ``gather_evidence`` phase must ground the investigation in what the
platform already knows: other alerts on the same host, the same IPs, the
same users. Without this the compression pipeline sees one event, the
causal graph has one node, and RCA can only answer "unknown".

Same lazy-pool pattern as :mod:`app.hunt.store`: raw asyncpg, best-effort —
a database outage never fails the investigation (we just return ``[]``).
Tenant isolation is enforced at the query layer (``WHERE tenant_id = …``)
per the platform convention.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import structlog

logger = structlog.get_logger()

_POOL = None  # type: ignore[var-annotated]

# Severity → risk_score ladder used when projecting alert rows into the
# event shape consumed by app.compression.stages.normalise_event.
_SEVERITY_RISK = {"critical": 0.95, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}


def _normalise_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace(
        "postgres+asyncpg://", "postgresql://"
    )


async def _get_pool():
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        logger.debug("platform_evidence.disabled", reason="DATABASE_URL not set")
        return None
    try:
        import asyncpg  # noqa: PLC0415 — keep optional for unit tests without the dep

        _POOL = await asyncpg.create_pool(
            dsn=_normalise_dsn(dsn), min_size=1, max_size=4, command_timeout=15
        )
        logger.info("platform_evidence.pool_initialised")
        return _POOL
    except Exception as exc:  # noqa: BLE001
        logger.warning("platform_evidence.pool_init_failed", error=str(exc))
        return None


async def close_pool() -> None:
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None


def _as_list(value: Any) -> list:
    """JSONB columns may arrive as list (codec) or JSON string — accept both."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return []
    return []


def _coerce_uuid(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError):
        return None


async def collect_related_alerts(
    *,
    tenant_id: str,
    hostnames: list[str] | None = None,
    ips: list[str] | None = None,
    users: list[str] | None = None,
    exclude_alert_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Fetch alerts sharing a host / IP / user with the one under investigation.

    Returns event-shaped dicts (``entity_id`` / ``timestamp`` / ``action`` /
    ``risk_score`` / ``mitre_technique_id`` …) ready for the compression
    pipeline's ``normalise_event`` and the RCA causal-graph builder.
    """
    pool = await _get_pool()
    if pool is None:
        return []

    tenant_uuid = _coerce_uuid(tenant_id)
    if tenant_uuid is None:
        logger.debug("platform_evidence.skipped", reason="non-uuid tenant ref")
        return []

    hosts = [h for h in {str(h).strip() for h in (hostnames or [])} if h][:10]
    addrs = [i for i in {str(i).strip() for i in (ips or [])} if i][:10]
    usrs = [u for u in {str(u).strip() for u in (users or [])} if u][:10]
    if not hosts and not addrs and not usrs:
        return []

    exclude_uuid = _coerce_uuid(exclude_alert_id)

    # JSONB `?|` matches rows whose array contains ANY of the given strings.
    # OCSF-shaped alerts often leave affected_* empty and carry the host at
    # raw_event.device.name, so match that path as well.
    sql = """
        SELECT id, title, severity, status, category, created_at,
               mitre_techniques, affected_hosts, affected_ips, affected_users,
               raw_event->'device'->>'name' AS device_name
        FROM alerts
        WHERE tenant_id = $1::uuid
          AND ($2::uuid IS NULL OR id <> $2::uuid)
          AND (
                (cardinality($3::text[]) > 0 AND affected_hosts ?| $3::text[])
             OR (cardinality($3::text[]) > 0
                 AND raw_event->'device'->>'name' = ANY($3::text[]))
             OR (cardinality($4::text[]) > 0 AND affected_ips   ?| $4::text[])
             OR (cardinality($5::text[]) > 0 AND affected_users ?| $5::text[])
          )
        ORDER BY created_at DESC
        LIMIT $6
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, tenant_uuid, exclude_uuid, hosts, addrs, usrs, limit)
    except Exception as exc:  # noqa: BLE001
        logger.warning("platform_evidence.query_failed", error=str(exc))
        return []

    events: list[dict[str, Any]] = []
    for row in rows:
        row_hosts = _as_list(row["affected_hosts"])
        if not row_hosts and row["device_name"]:
            row_hosts = [str(row["device_name"])]
        row_ips = _as_list(row["affected_ips"])
        row_users = _as_list(row["affected_users"])
        techniques = [str(t) for t in _as_list(row["mitre_techniques"])]
        entity = (
            (row_hosts[0] if row_hosts else None)
            or (row_ips[0] if row_ips else None)
            or (row_users[0] if row_users else None)
            or "unknown"
        )
        event: dict[str, Any] = {
            "alert_id": str(row["id"]),
            "entity_id": str(entity),
            "hostname": row_hosts[0] if row_hosts else None,
            "src_ip": row_ips[0] if row_ips else None,
            "username": row_users[0] if row_users else None,
            "title": row["title"],
            "action": row["title"],
            "event_type": row["category"] or "alert",
            "severity": row["severity"],
            "status": row["status"],
            "risk_score": _SEVERITY_RISK.get(str(row["severity"]).lower(), 0.3),
            "timestamp": row["created_at"].isoformat() if row["created_at"] else None,
            "mitre_techniques": techniques,
        }
        if techniques:
            event["mitre_technique_id"] = techniques[0]
        events.append(event)

    logger.info(
        "platform_evidence.collected",
        related_alerts=len(events),
        hosts=hosts,
        ips=addrs,
        users=usrs,
    )
    return events
