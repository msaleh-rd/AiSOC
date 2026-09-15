"""
abuse.ch Feodo Tracker client — active botnet C2 IP addresses.

Fetches the JSON IP blocklist and normalizes each entry into the
standard AiSOC IOC schema.  Zero credentials required.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerClient:
    """Async Feodo Tracker JSON feed client."""

    def __init__(self, url: str = _DEFAULT_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.json())
                logger.info("Feodo Tracker fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("Feodo Tracker fetch failed", error=str(exc))
                return []

    def parse(self, data: str | list[dict[str, Any]] | dict) -> list[dict[str, Any]]:
        """Parse Feodo Tracker JSON into normalized IOCs.

        Each entry has: ``ip_address``, ``port``, ``status``,
        ``hostname``, ``as_number``, ``as_name``, ``country``,
        ``first_seen``, ``last_online``, ``malware``.
        """
        iocs: list[dict[str, Any]] = []
        if isinstance(data, str):
            data = data.strip()
            if not data:
                return iocs
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                return iocs

        if not isinstance(data, (dict, list)):
            return iocs

        entries = data if isinstance(data, list) else data.get("data", data.get("entries", []))
        if not isinstance(entries, list):
            return iocs

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            status = entry.get("status")
            if status and str(status).strip().lower() == "offline":
                continue
            ip = entry.get("ip_address", "")
            if not ip:
                continue
            malware = entry.get("malware", "unknown")
            port = entry.get("port")
            tags = ["c2", "botnet", "feodotracker", "feodo"]
            if malware:
                tags.append(malware.lower().replace(" ", "_"))

            iocs.append(
                {
                    "type": "ipv4-addr",
                    "value": ip,
                    "description": f"{malware} botnet C2 server — Feodo Tracker",
                    "source": "feodotracker",
                    "source_ref": f"feodotracker:{ip}:{port or 0}",
                    "confidence": 90,
                    "tags": list(set(tags)),
                    "threat_type": "botnet_cc",
                    "malware_family": malware,
                    "port": port,
                    "as_number": entry.get("as_number"),
                    "as_name": entry.get("as_name", ""),
                    "country": entry.get("country", ""),
                    "first_seen": entry.get("first_seen", ""),
                    "last_online": entry.get("last_online", ""),
                    "status": entry.get("status", ""),
                    "tlp": "white",
                }
            )
        return iocs
