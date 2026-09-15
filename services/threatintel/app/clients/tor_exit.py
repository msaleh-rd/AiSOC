"""
Tor Project bulk exit node list client.

Fetches the official Tor exit node IP list and normalizes each entry
into the standard AiSOC IOC schema.  Zero credentials required.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_URL = "https://check.torproject.org/torbulkexitlist"


class TorExitClient:
    """Async Tor exit node list client."""

    def __init__(self, url: str = _DEFAULT_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.text)
                logger.info("Tor exit nodes fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("Tor exit node fetch failed", error=str(exc))
                return []

    def parse(self, body: str) -> list[dict[str, Any]]:
        """Parse one-IP-per-line list into normalized IOCs."""
        iocs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ip_obj = ipaddress.IPv4Address(line)
                ip = str(ip_obj)
            except ValueError:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            iocs.append(
                {
                    "type": "ipv4-addr",
                    "value": ip,
                    "description": "Tor exit node — traffic from this IP may be anonymized",
                    "source": "tor-exit",
                    "source_ref": f"tor-exit:{ip}",
                    "confidence": 95,
                    "tags": ["tor", "exit-node", "exit_node", "anonymizer"],
                    "threat_type": "anonymizer",
                    "tlp": "white",
                }
            )
        return iocs
