"""
Feed management and IOC lookup REST API.

Provides endpoints to monitor feed health, trigger manual syncs,
and query stored threat intelligence indicators.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["feeds", "iocs"])


# ── Request / Response schemas ────────────────────────────────────────────────


class IOCLookupRequest(BaseModel):
    """Batch IOC lookup request."""

    indicators: list[str] = Field(
        ...,
        description="List of indicator values (IPs, domains, hashes, URLs) to look up.",
        min_length=1,
        max_length=100,
    )


class IOCLookupResult(BaseModel):
    indicator: str
    found: bool
    matches: list[dict[str, Any]] = []


class IOCLookupResponse(BaseModel):
    total_queried: int
    total_found: int
    results: list[IOCLookupResult]


class FeedSyncResponse(BaseModel):
    feed_name: str
    triggered: bool
    message: str


class FeedSyncAllResponse(BaseModel):
    triggered: list[str]
    message: str


# ── Feed management endpoints ────────────────────────────────────────────────


@router.get("/feeds")
async def list_feeds(request: Request) -> dict[str, Any]:
    """List all registered threat intel feeds with status and scheduling info."""
    scheduler = request.app.state.scheduler
    statuses = scheduler.get_feed_statuses()
    return {
        "total": len(statuses),
        "feeds": list(statuses.values()),
    }


@router.get("/feeds/{feed_name}")
async def get_feed(request: Request, feed_name: str) -> dict[str, Any]:
    """Get status for a single feed."""
    scheduler = request.app.state.scheduler
    status_data = scheduler.get_feed_status(feed_name)
    if status_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_name}' not found",
        )
    return status_data


@router.post("/feeds/{feed_name}/sync", response_model=FeedSyncResponse)
async def sync_feed(request: Request, feed_name: str) -> FeedSyncResponse:
    """Trigger immediate background sync of a single feed."""
    scheduler = request.app.state.scheduler
    triggered = await scheduler.trigger_job(feed_name)
    if not triggered:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_name}' not found",
        )
    return FeedSyncResponse(
        feed_name=feed_name,
        triggered=True,
        message=f"Feed '{feed_name}' sync triggered in background",
    )


@router.post("/feeds/sync-all", response_model=FeedSyncAllResponse)
async def sync_all_feeds(request: Request) -> FeedSyncAllResponse:
    """Trigger immediate background sync of all registered feeds."""
    scheduler = request.app.state.scheduler
    triggered = await scheduler.trigger_all()
    return FeedSyncAllResponse(
        triggered=triggered,
        message=f"Triggered {len(triggered)} feeds",
    )


# ── IOC lookup endpoints ─────────────────────────────────────────────────────


@router.post("/iocs/lookup", response_model=IOCLookupResponse)
async def lookup_iocs(request: Request, body: IOCLookupRequest) -> IOCLookupResponse:
    """Query indicators against stored threat intelligence.

    Checks the OpenSearch index for matching IOCs and returns source,
    malware family, confidence, and tags for each match.
    """
    os_store = request.app.state.os_store
    results: list[IOCLookupResult] = []
    total_found = 0

    for indicator in body.indicators:
        try:
            matches = await os_store.search_iocs(value=indicator, limit=10)
            found = len(matches) > 0
            if found:
                total_found += 1
            results.append(
                IOCLookupResult(
                    indicator=indicator,
                    found=found,
                    matches=matches,
                )
            )
        except Exception as exc:
            logger.warning("IOC lookup error", indicator=indicator[:80], error=str(exc)[:200])
            results.append(
                IOCLookupResult(
                    indicator=indicator,
                    found=False,
                    matches=[],
                )
            )

    return IOCLookupResponse(
        total_queried=len(body.indicators),
        total_found=total_found,
        results=results,
    )


@router.get("/iocs/{ioc_type}/{value:path}")
async def get_ioc(request: Request, ioc_type: str, value: str) -> dict[str, Any]:
    """Quick single-indicator lookup by type and value."""
    os_store = request.app.state.os_store
    matches = await os_store.search_iocs(value=value, ioc_type=ioc_type, limit=10)
    return {
        "indicator": value,
        "type": ioc_type,
        "found": len(matches) > 0,
        "matches": matches,
    }


# ── Statistics endpoint ──────────────────────────────────────────────────────


@router.get("/stats")
async def threat_intel_stats(request: Request) -> dict[str, Any]:
    """Aggregate threat intelligence statistics."""
    scheduler = request.app.state.scheduler
    statuses = scheduler.get_feed_statuses()

    total_ingested = sum(s.get("items_ingested", 0) for s in statuses.values())
    total_deduped = sum(s.get("items_deduped", 0) for s in statuses.values())
    total_runs = sum(s.get("run_count", 0) for s in statuses.values())
    feeds_ok = sum(1 for s in statuses.values() if s.get("state") == "success")
    feeds_error = sum(1 for s in statuses.values() if s.get("state") == "error")
    feeds_running = sum(1 for s in statuses.values() if s.get("state") == "running")

    return {
        "total_feeds": len(statuses),
        "feeds_ok": feeds_ok,
        "feeds_error": feeds_error,
        "feeds_running": feeds_running,
        "total_runs": total_runs,
        "total_items_ingested": total_ingested,
        "total_items_deduped": total_deduped,
    }
