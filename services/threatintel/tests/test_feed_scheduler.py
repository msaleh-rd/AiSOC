"""
Unit tests for FeedScheduler (startup execution, status tracking, manual triggers).

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.feeds.scheduler import FeedScheduler, FeedStatus


def test_feed_status_to_dict():
    status = FeedStatus("test-feed", interval_seconds=300)
    data = status.to_dict()
    assert data["feed_name"] == "test-feed"
    assert data["interval_seconds"] == 300
    assert data["state"] == "idle"
    assert data["run_count"] == 0
    assert data["items_ingested"] == 0
    assert data["last_error"] == ""


@pytest.mark.asyncio
async def test_scheduler_register_and_status():
    pipeline = MagicMock()
    scheduler = FeedScheduler(pipeline, run_on_startup=False)

    async def sample_handler():
        pass

    scheduler.register("test-feed-1", sample_handler, interval_seconds=600)
    scheduler.register("test-feed-2", sample_handler, interval_seconds=1200)

    statuses = scheduler.get_feed_statuses()
    assert "test-feed-1" in statuses
    assert "test-feed-2" in statuses
    assert statuses["test-feed-1"]["interval_seconds"] == 600
    assert statuses["test-feed-2"]["interval_seconds"] == 1200
    assert statuses["test-feed-1"]["state"] == "idle"

    single = scheduler.get_feed_status("test-feed-1")
    assert single is not None
    assert single["feed_name"] == "test-feed-1"
    assert scheduler.get_feed_status("unknown") is None


@pytest.mark.asyncio
async def test_scheduler_trigger_job_success():
    pipeline = MagicMock()
    scheduler = FeedScheduler(pipeline, run_on_startup=False)

    ran = False

    async def success_handler():
        nonlocal ran
        ran = True

    scheduler.register("success-feed", success_handler, interval_seconds=300)

    triggered = await scheduler.trigger_job("success-feed", wait=True)
    assert triggered is True
    assert ran is True

    status = scheduler.get_feed_status("success-feed")
    assert status is not None
    assert status["state"] == "success"
    assert status["run_count"] == 1
    assert status["last_run_start"] is not None
    assert status["last_run_end"] is not None
    assert status["last_error"] == ""


@pytest.mark.asyncio
async def test_scheduler_trigger_job_failure():
    pipeline = MagicMock()
    scheduler = FeedScheduler(pipeline, run_on_startup=False)

    async def failing_handler():
        raise RuntimeError("simulated network failure")

    scheduler.register("failing-feed", failing_handler, interval_seconds=300)

    triggered = await scheduler.trigger_job("failing-feed", wait=True)
    assert triggered is True

    status = scheduler.get_feed_status("failing-feed")
    assert status is not None
    assert status["state"] == "error"
    assert "simulated network failure" in status["last_error"]
    assert status["run_count"] == 1


@pytest.mark.asyncio
async def test_scheduler_trigger_unknown_returns_false():
    pipeline = MagicMock()
    scheduler = FeedScheduler(pipeline, run_on_startup=False)
    assert await scheduler.trigger_job("non-existent") is False


@pytest.mark.asyncio
async def test_scheduler_trigger_all():
    pipeline = MagicMock()
    scheduler = FeedScheduler(pipeline, run_on_startup=False)

    counts = {"f1": 0, "f2": 0}

    async def h1():
        counts["f1"] += 1

    async def h2():
        counts["f2"] += 1

    scheduler.register("f1", h1, 300)
    scheduler.register("f2", h2, 600)

    triggered = await scheduler.trigger_all(wait=True)
    assert set(triggered) == {"f1", "f2"}
    assert counts["f1"] == 1
    assert counts["f2"] == 1
