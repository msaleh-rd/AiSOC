"""
abuse.ch URLhaus client — malware distribution site URLs.

Fetches the recent CSV export (last 30 days) and normalizes each entry
into the standard AiSOC IOC schema.  Zero credentials required.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import csv
import io
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


class UrlhausClient:
    """Async URLhaus CSV feed client."""

    def __init__(self, url: str = _DEFAULT_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.text)
                logger.info("URLhaus fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("URLhaus fetch failed", error=str(exc))
                return []

    def parse(self, body: str) -> list[dict[str, Any]]:
        """Parse URLhaus CSV into normalized IOCs.

        The CSV uses ``#`` comment lines for the header preamble; actual
        data rows have columns:
          id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        """
        iocs: list[dict[str, Any]] = []
        # Strip comment lines
        lines = [ln for ln in body.splitlines() if ln and not ln.startswith("#")]
        if not lines:
            return iocs

        reader = csv.reader(io.StringIO("\n".join(lines)))
        for row in reader:
            if len(row) < 8:
                continue
            url_id, dateadded, url_val, url_status, _last_online, threat, tags_str, urlhaus_link, *_ = row
            if not url_val or url_status == "offline":
                continue
            tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []
            tags.extend(["malware", "urlhaus"])
            if threat:
                tags.append(threat)
            iocs.append(
                {
                    "type": "url",
                    "value": url_val,
                    "description": f"Malware distribution URL ({threat or 'unknown'}) — URLhaus #{url_id}",
                    "source": "urlhaus",
                    "source_ref": f"urlhaus:{url_id}",
                    "confidence": 85,
                    "tags": list(set(tags)),
                    "threat_type": threat or "malware_distribution",
                    "first_seen": dateadded,
                    "urlhaus_id": url_id,
                    "urlhaus_link": urlhaus_link,
                    "tlp": "white",
                }
            )
        return iocs
