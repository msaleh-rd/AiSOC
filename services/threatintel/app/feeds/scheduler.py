"""
APScheduler-based feed polling orchestrator.

Coordinates all threat intelligence feed polling intervals, tracks
per-feed status (idle / running / success / error), supports immediate
startup execution (staggered), and exposes on-demand manual triggers.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline

logger = structlog.get_logger(__name__)


class FeedStatus:
    """Per-feed runtime status tracker."""

    __slots__ = (
        "feed_name",
        "interval_seconds",
        "state",
        "last_run_start",
        "last_run_end",
        "last_duration_ms",
        "last_error",
        "items_ingested",
        "items_deduped",
        "run_count",
    )

    def __init__(self, feed_name: str, interval_seconds: int) -> None:
        self.feed_name = feed_name
        self.interval_seconds = interval_seconds
        self.state: str = "idle"  # idle | running | success | error
        self.last_run_start: datetime | None = None
        self.last_run_end: datetime | None = None
        self.last_duration_ms: float = 0.0
        self.last_error: str = ""
        self.items_ingested: int = 0
        self.items_deduped: int = 0
        self.run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        next_run: str | None = None
        if self.last_run_end and self.state in ("success", "error"):
            next_dt = self.last_run_end + timedelta(seconds=self.interval_seconds)
            next_run = next_dt.isoformat()

        return {
            "feed_name": self.feed_name,
            "interval_seconds": self.interval_seconds,
            "state": self.state,
            "last_run_start": self.last_run_start.isoformat() if self.last_run_start else None,
            "last_run_end": self.last_run_end.isoformat() if self.last_run_end else None,
            "last_duration_ms": round(self.last_duration_ms, 1),
            "last_error": self.last_error,
            "items_ingested": self.items_ingested,
            "items_deduped": self.items_deduped,
            "run_count": self.run_count,
            "next_run": next_run,
        }


class FeedScheduler:
    """
    Manages periodic polling of all threat intelligence feeds.

    Each feed has its own job with a configurable interval so that
    high-frequency feeds (e.g., TAXII every 15 min) and low-frequency
    feeds (CISA KEV once a day) can coexist without contention.

    Enhancements over the baseline scheduler:
    - **Immediate startup execution**: Feeds fire once on boot (staggered)
      rather than waiting for their full interval.
    - **Status registry**: Per-feed status tracking (state, timing, counts).
    - **Manual triggers**: ``trigger_job`` / ``trigger_all`` for on-demand sync.
    """

    def __init__(
        self,
        pipeline: ThreatIntelPipeline,
        *,
        run_on_startup: bool = True,
        startup_stagger_seconds: int = 5,
    ) -> None:
        self._pipeline = pipeline
        self._scheduler = AsyncIOScheduler()
        self._run_on_startup = run_on_startup
        self._startup_stagger_seconds = startup_stagger_seconds
        self._statuses: dict[str, FeedStatus] = {}
        self._handlers: dict[str, Callable] = {}
        self._registration_order: list[str] = []

    # ── Registration ──────────────────────────────────────────────────────

    def register(
        self,
        feed_name: str,
        handler: Callable,
        interval_seconds: int,
    ) -> None:
        """Register a feed polling function with status tracking."""
        # Wrap the handler to track status
        wrapped = self._wrap_handler(feed_name, handler)

        # Calculate first run time — staggered startup
        if self._run_on_startup:
            stagger = len(self._registration_order) * self._startup_stagger_seconds
            next_run = datetime.now(UTC) + timedelta(seconds=stagger)
        else:
            next_run = None

        kwargs: dict[str, Any] = {
            "func": wrapped,
            "trigger": IntervalTrigger(seconds=interval_seconds),
            "id": feed_name,
            "name": f"Feed: {feed_name}",
            "replace_existing": True,
            "max_instances": 1,
            "coalesce": True,
        }
        if next_run is not None:
            kwargs["next_run_time"] = next_run

        self._scheduler.add_job(**kwargs)
        self._statuses[feed_name] = FeedStatus(feed_name, interval_seconds)
        self._handlers[feed_name] = handler
        self._registration_order.append(feed_name)
        logger.info(
            "Registered feed",
            feed=feed_name,
            interval_seconds=interval_seconds,
            startup_delay_s=stagger if self._run_on_startup else "disabled",
        )

    # ── Handler wrapper ───────────────────────────────────────────────────

    def _wrap_handler(self, feed_name: str, handler: Callable) -> Callable:
        """Wrap a feed handler to track status + timing."""

        async def _tracked() -> None:
            status = self._statuses.get(feed_name)
            if not status:
                await handler()
                return

            status.state = "running"
            status.last_run_start = datetime.now(UTC)
            status.last_error = ""
            t0 = time.monotonic()

            try:
                await handler()
                status.state = "success"
            except Exception as exc:
                status.state = "error"
                status.last_error = str(exc)[:500]
                logger.error("Feed handler failed", feed=feed_name, error=str(exc)[:200])
            finally:
                elapsed = (time.monotonic() - t0) * 1000
                status.last_run_end = datetime.now(UTC)
                status.last_duration_ms = elapsed
                status.run_count += 1

        return _tracked

    # ── Manual triggers ───────────────────────────────────────────────────

    async def trigger_job(self, feed_name: str, wait: bool = False) -> bool:
        """Trigger an immediate, one-off execution of a named feed.

        If ``wait`` is True, awaits completion before returning.
        Returns True if the feed exists and was triggered.
        """
        if feed_name not in self._handlers:
            return False

        handler = self._handlers[feed_name]
        wrapped = self._wrap_handler(feed_name, handler)
        if wait:
            await wrapped()
        else:
            asyncio.create_task(wrapped())
        logger.info("Manual feed trigger", feed=feed_name)
        return True

    async def trigger_all(self, wait: bool = False) -> list[str]:
        """Trigger immediate execution of all registered feeds.

        Returns list of feed names that were triggered.
        """
        triggered: list[str] = []
        tasks = []
        for feed_name in self._registration_order:
            if feed_name in self._handlers:
                handler = self._handlers[feed_name]
                wrapped = self._wrap_handler(feed_name, handler)
                if wait:
                    tasks.append(wrapped())
                else:
                    asyncio.create_task(wrapped())
                triggered.append(feed_name)
        if wait and tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Manual trigger all feeds", count=len(triggered))
        return triggered

    # ── Status queries ────────────────────────────────────────────────────

    def get_feed_statuses(self) -> dict[str, dict[str, Any]]:
        """Return current status dict for all registered feeds."""
        return {name: status.to_dict() for name, status in self._statuses.items()}

    def get_feed_status(self, feed_name: str) -> dict[str, Any] | None:
        """Return status for a single feed, or None if unknown."""
        status = self._statuses.get(feed_name)
        return status.to_dict() if status else None

    @property
    def feed_names(self) -> list[str]:
        """List of registered feed names in registration order."""
        return list(self._registration_order)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the scheduler (non-blocking in async context)."""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("Feed scheduler started", feeds=len(self._statuses))

    def stop(self) -> None:
        """Gracefully stop the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("Feed scheduler stopped")
