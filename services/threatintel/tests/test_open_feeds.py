"""
Parse contracts for the zero-credential public feeds (OpenPhish, Spamhaus
DROP). Pure parsing — no network. The fetch path degrades gracefully on
error (returns []), which the airgap tests already cover at the policy level.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from app.feeds.handlers import OpenPhishClient, SpamhausDropClient

# ─── OpenPhish ────────────────────────────────────────────────────────────────

_OPENPHISH_BODY = """\
https://evil.example.com/login
http://phish.example.net/verify?id=1

not-a-url
ftp://ignored.example.org/file
https://another.example.io/reset
"""


def test_openphish_parse_extracts_only_http_urls():
    iocs = OpenPhishClient().parse(_OPENPHISH_BODY)
    assert [i["value"] for i in iocs] == [
        "https://evil.example.com/login",
        "http://phish.example.net/verify?id=1",
        "https://another.example.io/reset",
    ]


def test_openphish_ioc_shape():
    ioc = OpenPhishClient().parse("https://evil.example.com/a")[0]
    assert ioc["type"] == "url"
    assert ioc["source"] == "openphish"
    assert ioc["source_ref"] == "openphish:https://evil.example.com/a"
    assert "phishing" in ioc["tags"]
    assert ioc["tlp"] == "white"


def test_openphish_parse_empty_body():
    assert OpenPhishClient().parse("") == []


# ─── Spamhaus DROP ────────────────────────────────────────────────────────────

_DROP_BODY = """\
{"cidr":"192.0.2.0/24","sblid":"SBL123456","rir":"arin"}
{"cidr":"198.51.100.0/22","sblid":"SBL654321","rir":"ripencc"}
not json at all
{"type":"metadata","timestamp":1757800000,"size":2,"copyright":"(c) Spamhaus"}
"""


def test_spamhaus_drop_parse_extracts_netblocks_and_skips_metadata():
    iocs = SpamhausDropClient().parse(_DROP_BODY)
    assert [i["value"] for i in iocs] == ["192.0.2.0/24", "198.51.100.0/22"]


def test_spamhaus_drop_ioc_shape():
    ioc = SpamhausDropClient().parse(_DROP_BODY)[0]
    assert ioc["type"] == "cidr"
    assert ioc["source"] == "spamhaus-drop"
    assert ioc["sbl_id"] == "SBL123456"
    assert ioc["rir"] == "arin"
    assert ioc["source_ref"] == "spamhaus-drop:SBL123456"
    assert "drop" in ioc["tags"]
    assert ioc["tlp"] == "white"


def test_spamhaus_drop_parse_empty_body():
    assert SpamhausDropClient().parse("") == []
