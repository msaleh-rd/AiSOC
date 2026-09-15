"""
HTTP-level tests for the feeds management and IOC lookup API (/api/v1/feeds/* and /api/v1/iocs/*).

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.feeds import router


def _create_app(scheduler=None, os_store=None) -> FastAPI:
    app = FastAPI()
    app.state.scheduler = scheduler or MagicMock()
    app.state.os_store = os_store or MagicMock()
    app.include_router(router)
    return app


def test_list_feeds():
    scheduler = MagicMock()
    scheduler.get_feed_statuses.return_value = {
        "urlhaus": {
            "feed_name": "urlhaus",
            "interval_seconds": 1800,
            "state": "idle",
            "items_ingested": 100,
        },
        "threatfox": {
            "feed_name": "threatfox",
            "interval_seconds": 1800,
            "state": "success",
            "items_ingested": 250,
        },
    }

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.get("/api/v1/feeds")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["feeds"]) == 2


def test_get_single_feed_success():
    scheduler = MagicMock()
    scheduler.get_feed_status.return_value = {
        "feed_name": "cisa-kev",
        "interval_seconds": 86400,
        "state": "success",
        "items_ingested": 1200,
    }

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.get("/api/v1/feeds/cisa-kev")
    assert resp.status_code == 200
    assert resp.json()["feed_name"] == "cisa-kev"


def test_get_single_feed_not_found():
    scheduler = MagicMock()
    scheduler.get_feed_status.return_value = None

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.get("/api/v1/feeds/non-existent")
    assert resp.status_code == 404


def test_sync_feed_success():
    scheduler = MagicMock()
    scheduler.trigger_job = AsyncMock(return_value=True)

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.post("/api/v1/feeds/urlhaus/sync")
    assert resp.status_code == 200
    data = resp.json()
    assert data["feed_name"] == "urlhaus"
    assert data["triggered"] is True


def test_sync_feed_not_found():
    scheduler = MagicMock()
    scheduler.trigger_job = AsyncMock(return_value=False)

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.post("/api/v1/feeds/unknown/sync")
    assert resp.status_code == 404


def test_sync_all_feeds():
    scheduler = MagicMock()
    scheduler.trigger_all = AsyncMock(return_value=["urlhaus", "threatfox", "feodotracker"])

    app = _create_app(scheduler=scheduler)
    client = TestClient(app)

    resp = client.post("/api/v1/feeds/sync-all")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["triggered"]) == 3
    assert "urlhaus" in data["triggered"]


def test_lookup_iocs():
    os_store = MagicMock()

    async def mock_search(value, limit=10):
        if value == "198.51.100.50":
            return (1, [
                {
                    "type": "ipv4-addr",
                    "value": "198.51.100.50",
                    "source": "threatfox",
                    "malware_family": "Cobalt Strike",
                    "confidence": 95,
                }
            ])
        return (0, [])

    os_store.search_iocs = AsyncMock(side_effect=mock_search)

    app = _create_app(os_store=os_store)
    client = TestClient(app)

    resp = client.post(
        "/api/v1/iocs/lookup",
        json={"indicators": ["198.51.100.50", "8.8.8.8"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_queried"] == 2
    assert data["total_found"] == 1

    results = {r["indicator"]: r for r in data["results"]}
    assert results["198.51.100.50"]["found"] is True
    assert len(results["198.51.100.50"]["matches"]) == 1
    assert results["8.8.8.8"]["found"] is False
    assert len(results["8.8.8.8"]["matches"]) == 0
