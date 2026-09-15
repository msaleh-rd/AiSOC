"""
Feed handler functions for each threat intelligence source.

Each handler is registered with the FeedScheduler and invoked on
its configured polling interval. Handlers fetch from their source,
parse/normalize the data, and hand off to ThreatIntelPipeline.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from app.clients.cisa_kev import CisaKevClient
from app.clients.misp import MispClient
from app.clients.otx import OtxClient
from app.clients.taxii import TaxiiClient
from app.parsers.stix import StixParser

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline

logger = structlog.get_logger(__name__)


# ─── TAXII Feed Handler ───────────────────────────────────────────────────────


async def handle_taxii_feed(
    client: TaxiiClient,
    pipeline: ThreatIntelPipeline,
    api_root: str,
    collection_id: str,
) -> None:
    """
    Fetch STIX bundle from TAXII 2.1 endpoint and ingest into pipeline.
    """
    source_label = f"taxii:{collection_id[:8]}"
    logger.info("Polling TAXII feed", collection=collection_id)

    try:
        objects = await client.get_objects(api_root, collection_id)
        if not objects:
            logger.debug("TAXII feed empty", collection=collection_id)
            return

        parser = StixParser(objects)
        iocs = parser.extract_iocs()
        actors = parser.extract_actors()
        relationships = parser.extract_relationships()

        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source=source_label)
            logger.info("TAXII IOCs ingested", **stats)

        if actors:
            stats = await pipeline.ingest_actors(actors, source=source_label)
            logger.info("TAXII actors ingested", **stats)

        if relationships:
            count = await pipeline.ingest_relationships(relationships, source=source_label)
            logger.info("TAXII relationships ingested", count=count)

    except Exception as exc:
        logger.error("TAXII feed handler failed", collection=collection_id, error=str(exc))


# ─── MISP Feed Handler ────────────────────────────────────────────────────────


async def handle_misp_feed(
    client: MispClient,
    pipeline: ThreatIntelPipeline,
    since_hours: int = 24,
) -> None:
    """
    Fetch recent MISP events and extract IOCs.
    """
    logger.info("Polling MISP feed", since_hours=since_hours)

    try:
        events = await client.get_recent_events(since_hours=since_hours)
        all_iocs: list[dict[str, Any]] = []
        for event in events:
            all_iocs.extend(client.extract_iocs(event))

        if all_iocs:
            stats = await pipeline.ingest_iocs(all_iocs, source="misp")
            logger.info("MISP IOCs ingested", **stats, event_count=len(events))

    except Exception as exc:
        logger.error("MISP feed handler failed", error=str(exc))


# ─── OTX Feed Handler ─────────────────────────────────────────────────────────


async def handle_otx_feed(
    client: OtxClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """
    Fetch subscribed OTX pulses and extract IOC indicators.
    """
    logger.info("Polling OTX feed")

    try:
        pulses = await client.get_subscribed_pulses(limit=100)
        all_iocs: list[dict[str, Any]] = []
        for pulse in pulses:
            all_iocs.extend(client.extract_iocs(pulse))

        if all_iocs:
            stats = await pipeline.ingest_iocs(all_iocs, source="otx")
            logger.info("OTX IOCs ingested", **stats, pulse_count=len(pulses))

    except Exception as exc:
        logger.error("OTX feed handler failed", error=str(exc))


# ─── CISA KEV Feed Handler ────────────────────────────────────────────────────


async def handle_cisa_kev_feed(
    client: CisaKevClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """
    Fetch CISA KEV catalog and ingest vulnerability IOCs.
    """
    logger.info("Polling CISA KEV feed")

    try:
        entries = await client.fetch()
        iocs = [client.to_ioc(e) for e in entries]

        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source="cisa-kev")
            logger.info("CISA KEV IOCs ingested", **stats)

    except Exception as exc:
        logger.error("CISA KEV feed handler failed", error=str(exc))


# ─── Zero-credential public feeds (auto-on, no API key) ──────────────────────
#
# OpenPhish + Spamhaus DROP need no credentials, so a fresh install gets
# live, auto-updating intel out of the box alongside CISA KEV. Fetch and
# parse are split so tests can exercise parsing without network.

_OPENPHISH_URL = "https://openphish.com/feed.txt"
_SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"


class OpenPhishClient:
    """OpenPhish community feed — one confirmed phishing URL per line."""

    def __init__(self, url: str = _OPENPHISH_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.text)
                logger.info("OpenPhish fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("OpenPhish fetch failed", error=str(exc))
                return []

    def parse(self, body: str) -> list[dict[str, Any]]:
        iocs: list[dict[str, Any]] = []
        for line in body.splitlines():
            url = line.strip()
            if not url or not url.lower().startswith(("http://", "https://")):
                continue
            iocs.append(
                {
                    "type": "url",
                    "value": url,
                    "description": "Confirmed phishing URL (OpenPhish community feed)",
                    "source": "openphish",
                    "source_ref": f"openphish:{url}",
                    "tags": ["phishing", "openphish"],
                    "tlp": "white",
                }
            )
        return iocs


class SpamhausDropClient:
    """Spamhaus DROP — hijacked / criminal-controlled netblocks (JSON Lines)."""

    def __init__(self, url: str = _SPAMHAUS_DROP_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.text)
                logger.info("Spamhaus DROP fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("Spamhaus DROP fetch failed", error=str(exc))
                return []

    def parse(self, body: str) -> list[dict[str, Any]]:
        iocs: list[dict[str, Any]] = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            # The feed's trailing line is a metadata record, not a netblock.
            cidr = entry.get("cidr")
            if not isinstance(cidr, str) or not cidr:
                continue
            sblid = entry.get("sblid", "")
            iocs.append(
                {
                    "type": "cidr",
                    "value": cidr,
                    "description": "Hostile netblock on the Spamhaus Don't Route Or Peer list",
                    "sbl_id": sblid,
                    "rir": entry.get("rir", ""),
                    "source": "spamhaus-drop",
                    "source_ref": f"spamhaus-drop:{sblid or cidr}",
                    "tags": ["drop", "spamhaus", "netblock"],
                    "tlp": "white",
                }
            )
        return iocs


async def handle_openphish_feed(
    client: OpenPhishClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """Fetch the OpenPhish community feed and ingest URL IOCs."""
    logger.info("Polling OpenPhish feed")

    try:
        iocs = await client.fetch()
        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source="openphish")
            logger.info("OpenPhish IOCs ingested", **stats)

    except Exception as exc:
        logger.error("OpenPhish feed handler failed", error=str(exc))


async def handle_spamhaus_drop_feed(
    client: SpamhausDropClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """Fetch the Spamhaus DROP list and ingest netblock IOCs."""
    logger.info("Polling Spamhaus DROP feed")

    try:
        iocs = await client.fetch()
        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source="spamhaus-drop")
            logger.info("Spamhaus DROP IOCs ingested", **stats)

    except Exception as exc:
        logger.error("Spamhaus DROP feed handler failed", error=str(exc))
