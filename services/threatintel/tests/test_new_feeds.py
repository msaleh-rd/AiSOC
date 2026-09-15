"""
Parse contracts and schema normalization tests for the new zero-credential
public feeds: URLhaus, ThreatFox, Feodo Tracker, and Tor Exit Nodes.

Pure parsing — no network required.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
from app.clients.feodotracker import FeodoTrackerClient
from app.clients.threatfox import ThreatFoxClient
from app.clients.tor_exit import TorExitClient
from app.clients.urlhaus import UrlhausClient

# ─── URLhaus ──────────────────────────────────────────────────────────────────

_URLHAUS_CSV = """\
# ##################################################################
# abuse.ch URLhaus Database
# Last updated: 2026-09-15 00:00:00 UTC
# ##################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1001","2026-09-15 01:00:00","http://malware-drop.example/payload.exe","online","2026-09-15 01:05:00","malware_download","exe,Mozi","https://urlhaus.abuse.ch/url/1001/","reporter1"
"1002","2026-09-15 01:10:00","http://dead-link.example/bad.bin","offline","2026-09-14 12:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/1002/","reporter2"
"1003","2026-09-15 01:20:00","https://c2-site.example/gate.php","online","2026-09-15 01:25:00","malware_download","mirai,c2","https://urlhaus.abuse.ch/url/1003/","reporter3"
"""


def test_urlhaus_parse_filters_offline_and_extracts_online():
    client = UrlhausClient()
    iocs = client.parse(_URLHAUS_CSV)
    assert len(iocs) == 2
    urls = [i["value"] for i in iocs]
    assert "http://malware-drop.example/payload.exe" in urls
    assert "https://c2-site.example/gate.php" in urls
    assert "http://dead-link.example/bad.bin" not in urls


def test_urlhaus_ioc_normalization_shape():
    client = UrlhausClient()
    iocs = client.parse(_URLHAUS_CSV)
    ioc = iocs[0]
    assert ioc["type"] == "url"
    assert ioc["source"] == "urlhaus"
    assert ioc["source_ref"] == "urlhaus:1001"
    assert "exe" in ioc["tags"]
    assert "Mozi" in ioc["tags"]
    assert ioc["tlp"] == "white"
    assert ioc["urlhaus_id"] == "1001"


def test_urlhaus_empty_body():
    client = UrlhausClient()
    assert client.parse("") == []
    assert client.parse("# only comments\n# nothing else") == []


# ─── ThreatFox ────────────────────────────────────────────────────────────────

_THREATFOX_JSON = json.dumps({
    "query_status": "ok",
    "data": [
        {
            "id": "2001",
            "ioc": "198.51.100.50:8080",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet Command and Control Server",
            "ioc_type": "ip:port",
            "ioc_type_desc": "IP address and port of a botnet C&C",
            "malware": "cobalt_strike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 95,
            "first_seen": "2026-09-15 00:00:00 UTC",
            "last_seen": "2026-09-15 01:00:00 UTC",
            "reporter": "abuse_ch",
            "tags": ["CobaltStrike", "beacon"],
        },
        {
            "id": "2002",
            "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Malware payload hash",
            "ioc_type": "sha256_hash",
            "ioc_type_desc": "SHA256 hash of a malware sample",
            "malware": "redline_stealer",
            "malware_printable": "RedLine Stealer",
            "confidence_level": 100,
            "first_seen": "2026-09-15 02:00:00 UTC",
            "last_seen": None,
            "reporter": "analyst1",
            "tags": ["RedLine", "stealer"],
        },
    ]
})


def test_threatfox_parse_normalizes_iocs():
    client = ThreatFoxClient()
    iocs = client.parse(_THREATFOX_JSON)
    assert len(iocs) == 2

    # IP check (ip:port stripped of port for ipv4-addr type)
    ip_ioc = iocs[0]
    assert ip_ioc["type"] == "ipv4-addr"
    assert ip_ioc["value"] == "198.51.100.50"
    assert ip_ioc["port"] == 8080
    assert ip_ioc["source"] == "threatfox"
    assert ip_ioc["source_ref"] == "threatfox:2001"
    assert ip_ioc["malware_family"] == "Cobalt Strike"
    assert ip_ioc["confidence"] == 95
    assert "CobaltStrike" in ip_ioc["tags"]

    # Hash check
    hash_ioc = iocs[1]
    assert hash_ioc["type"] == "file-hash:SHA-256"
    assert hash_ioc["value"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_ioc["malware_family"] == "RedLine Stealer"
    assert hash_ioc["confidence"] == 100


def test_threatfox_empty_or_invalid():
    client = ThreatFoxClient()
    assert client.parse("") == []
    assert client.parse("{}") == []
    assert client.parse("not json") == []


# ─── Feodo Tracker ────────────────────────────────────────────────────────────

_FEODO_JSON = json.dumps([
    {
        "ip_address": "192.0.2.100",
        "port": 443,
        "status": "online",
        "hostname": "c2.example.com",
        "as_number": 64496,
        "as_name": "TEST-AS",
        "country": "US",
        "first_seen": "2026-09-14 10:00:00",
        "last_online": "2026-09-15 02:00:00",
        "malware": "QakBot",
    },
    {
        "ip_address": "192.0.2.101",
        "port": 2222,
        "status": "offline",
        "hostname": "dead-c2.example.com",
        "as_number": 64496,
        "as_name": "TEST-AS",
        "country": "US",
        "first_seen": "2026-09-10 10:00:00",
        "last_online": "2026-09-11 02:00:00",
        "malware": "Emotet",
    },
])


def test_feodotracker_parse_filters_offline():
    client = FeodoTrackerClient()
    iocs = client.parse(json.loads(_FEODO_JSON))
    assert len(iocs) == 1
    ioc = iocs[0]
    assert ioc["type"] == "ipv4-addr"
    assert ioc["value"] == "192.0.2.100"
    assert ioc["port"] == 443
    assert ioc["source"] == "feodotracker"
    assert ioc["source_ref"] == "feodotracker:192.0.2.100:443"
    assert ioc["malware_family"] == "QakBot"
    assert "feodo" in ioc["tags"]
    assert "qakbot" in ioc["tags"]
    assert ioc["tlp"] == "white"


def test_feodotracker_empty_or_dict():
    client = FeodoTrackerClient()
    assert client.parse([]) == []
    assert client.parse({}) == []


# ─── Tor Exit Nodes ───────────────────────────────────────────────────────────

_TOR_EXIT_BODY = """\
# Tor bulk exit list
198.51.100.1
198.51.100.2
not-an-ip
256.300.400.500
198.51.100.3
"""


def test_tor_exit_parse_validates_ips():
    client = TorExitClient()
    iocs = client.parse(_TOR_EXIT_BODY)
    assert len(iocs) == 3
    assert [i["value"] for i in iocs] == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    for ioc in iocs:
        assert ioc["type"] == "ipv4-addr"
        assert ioc["source"] == "tor-exit"
        assert "tor" in ioc["tags"]
        assert "exit-node" in ioc["tags"]
        assert "anonymizer" in ioc["tags"]
        assert ioc["tlp"] == "white"


def test_tor_exit_empty():
    client = TorExitClient()
    assert client.parse("") == []
    assert client.parse("# only comments\n") == []
