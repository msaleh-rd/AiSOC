"""
abuse.ch ThreatFox client — IOCs associated with known malware families.

Fetches the recent JSON export and normalizes each entry into the
standard AiSOC IOC schema.  Zero credentials required.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_URL = "https://threatfox.abuse.ch/export/json/recent/"

# ThreatFox ioc_type → AiSOC type mapping
_TYPE_MAP = {
    "ip:port": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "md5_hash": "file-hash:MD5",
    "sha256_hash": "file-hash:SHA-256",
    "sha1_hash": "file-hash:SHA-1",
}


class ThreatFoxClient:
    """Async ThreatFox JSON feed client."""

    def __init__(self, url: str = _DEFAULT_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                iocs = self.parse(resp.json())
                logger.info("ThreatFox fetched", count=len(iocs))
                return iocs
            except Exception as exc:
                logger.error("ThreatFox fetch failed", error=str(exc))
                return []

    def parse(self, data: str | dict[str, Any] | list) -> list[dict[str, Any]]:
        """Parse ThreatFox JSON into normalized IOCs.

        ThreatFox returns ``{"query_status": "ok", "data": [...]}``.
        Each entry has keys: ``ioc``, ``ioc_type``, ``threat_type``,
        ``malware``, ``malware_printable``, ``malware_alias``,
        ``malware_malpedia``, ``confidence_level``, ``first_seen_utc``,
        ``last_seen_utc``, ``reference``, ``reporter``, ``tags``.
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

        entries = data if isinstance(data, list) else data.get("data", [])
        if not isinstance(entries, list):
            return iocs

        for entry in entries:
            raw_type = entry.get("ioc_type", "")
            ioc_type = _TYPE_MAP.get(raw_type, "")
            if not ioc_type:
                continue

            value = entry.get("ioc", "")
            if not value:
                continue

            port = None
            # For ip:port entries, strip the port for the IOC value
            if raw_type == "ip:port" and ":" in value:
                parts = value.rsplit(":", 1)
                value = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None

            malware = entry.get("malware_printable", "") or entry.get("malware", "")
            tags = list(entry.get("tags", []) or [])
            tags.extend(["threatfox"])
            if malware:
                tags.append(malware.lower().replace(" ", "_"))

            confidence = entry.get("confidence_level", 70)
            if isinstance(confidence, str):
                try:
                    confidence = int(confidence)
                except ValueError:
                    confidence = 70

            ioc_dict: dict[str, Any] = {
                "type": ioc_type,
                "value": value,
                "description": f"{malware or 'Unknown malware'} IOC — ThreatFox",
                "source": "threatfox",
                "source_ref": f"threatfox:{entry.get('id', '')}",
                "confidence": min(max(confidence, 0), 100),
                "tags": list(set(tags)),
                "threat_type": entry.get("threat_type", ""),
                "malware_family": malware,
                "malware_alias": entry.get("malware_alias", ""),
                "first_seen": entry.get("first_seen_utc", ""),
                "last_seen": entry.get("last_seen_utc", ""),
                "reference": entry.get("reference", ""),
                "tlp": "white",
            }
            if port is not None:
                ioc_dict["port"] = port
            iocs.append(ioc_dict)
        return iocs
