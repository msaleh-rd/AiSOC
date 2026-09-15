"""Periodic Case Re-Correlation Worker.

Sweeps orphan alerts (case_id IS NULL) across active tenants that arrived
after the initial sliding window closed, and re-runs the CaseCorrelator
over a wider window (default 24h) to group them into active cases or open
new containers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.models.tenant import Tenant
from app.services.case_correlator import CaseCorrelator, CorrelationAction

logger = logging.getLogger(__name__)

__all__ = ["re_correlate_tenant", "run_once", "run_forever"]

# Polling cadence in seconds (default 15 minutes)
_DEFAULT_INTERVAL_SECONDS = 900
_DEFAULT_WINDOW_HOURS = 24.0


async def re_correlate_tenant(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    window_hours: float = _DEFAULT_WINDOW_HOURS,
    min_severity: str = "low",
    limit: int = 200,
) -> dict[str, int]:
    """Sweep orphan alerts for a single tenant and correlate them into Cases."""
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

    orphan_rows = (
        await db.execute(
            text("""
                SELECT id, tenant_id, title, description, severity, status,
                       mitre_tactics, mitre_techniques, affected_ips, affected_hosts,
                       affected_users, case_id, tags, enrichment_data, event_time
                FROM alerts
                WHERE tenant_id = :tenant_id
                  AND case_id IS NULL
                  AND created_at >= :cutoff
                ORDER BY event_time ASC
                LIMIT :limit
            """).bindparams(
                tenant_id=tenant_id,
                cutoff=cutoff,
                limit=limit,
            )
        )
    ).mappings().all()

    if not orphan_rows:
        return {"orphan_count": 0, "created": 0, "grouped": 0}

    correlator = CaseCorrelator(window=timedelta(hours=window_hours))
    created = 0
    grouped = 0

    for row in orphan_rows:
        alert_dict = dict(row)
        res = await correlator.correlate_alert(
            db,
            alert_dict,
            min_severity_for_new_case=min_severity,
        )
        if res.action == CorrelationAction.CREATED:
            created += 1
        elif res.action == CorrelationAction.GROUPED:
            grouped += 1

    logger.info(
        "case_re_correlator.tenant_swept",
        extra={
            "tenant_id": str(tenant_id).replace("\r", "").replace("\n", " ")[:36],
            "orphan_count": len(orphan_rows),
            "created": created,
            "grouped": grouped,
        },
    )
    return {"orphan_count": len(orphan_rows), "created": created, "grouped": grouped}


async def run_once(*, window_hours: float = _DEFAULT_WINDOW_HOURS) -> dict[str, int]:
    """Execute one full pass across all active tenants."""
    totals = {"tenants": 0, "orphan_count": 0, "created": 0, "grouped": 0}

    async with AsyncSessionLocal() as session:
        try:
            stmt = select(Tenant.id).where(Tenant.is_active.is_(True))
            result = await session.execute(stmt)
            tenant_ids = [row[0] for row in result.all()]
        except Exception as exc:  # noqa: BLE001
            logger.warning("case_re_correlator.fetch_tenants_failed: %s", exc)
            return totals

    for tid in tenant_ids:
        async with AsyncSessionLocal() as session:
            try:
                stats = await re_correlate_tenant(session, tid, window_hours=window_hours)
                totals["tenants"] += 1
                totals["orphan_count"] += stats["orphan_count"]
                totals["created"] += stats["created"]
                totals["grouped"] += stats["grouped"]
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "case_re_correlator.tenant_pass_failed for %s: %s",
                    tid,
                    exc,
                )

    return totals


async def run_forever() -> None:
    """Run the re-correlation loop indefinitely."""
    interval = int(
        os.environ.get(
            "CASE_RE_CORRELATOR_INTERVAL_SECONDS",
            str(_DEFAULT_INTERVAL_SECONDS),
        )
    )
    window_hours = float(
        os.environ.get("CASE_RE_CORRELATOR_WINDOW_HOURS", str(_DEFAULT_WINDOW_HOURS))
    )

    logger.info(
        "case_re_correlator worker starting: interval=%ds, window=%.1fh",
        interval,
        window_hours,
    )

    while True:
        try:
            await run_once(window_hours=window_hours)
        except asyncio.CancelledError:
            logger.info("case_re_correlator worker cancelled; exiting.")
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("case_re_correlator worker iteration failed: %s", exc)

        await asyncio.sleep(interval)
