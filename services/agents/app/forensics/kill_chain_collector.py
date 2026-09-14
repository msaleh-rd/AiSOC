"""Evidence-based 5-phase MITRE kill-chain collector and stage generator.

Ported from sxsecurityinvestigator/investigator/reporting/stage_collector.py
and scout.py for AiSOC. Evaluates Initial Access, Execution, Credential Access,
Discovery, and Lateral Movement with vector attribution and confidence scoring.
"""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any

from app.forensics.models import AttackStage, KillChainPhase

# Patterns indicating specific kill chain activities
_BRUTE_FORCE_PATTERNS = (
    "failed password", "authentication failure", "failed login",
    "invalid user", "pam_unix(sshd:auth): authentication failure",
    "preauth", "brute force", "password spray",
)

_VALID_ACCOUNT_PATTERNS = (
    "accepted password", "accepted publickey", "session opened for user",
    "logon successful", "successful authentication",
)

_CRED_ACCESS_PATTERNS = (
    "/etc/shadow", "/etc/security", "id_rsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", ".k5login", "puppet/ssl/private_keys",
    "mimikatz", "secretsdump", "procdump", "sam dump", "ntds.dit",
    "lsass", "vault/data",
)

_DISCOVERY_PATTERNS = (
    "nmap ", "masscan ", "zmap ", "netstat ", "ss -t", "arp -a",
    "find /", "find /var/log", "getent passwd", "cat /etc/passwd",
    "whoami", "ip a", "ifconfig", "hostname",
)

_LATERAL_MOVEMENT_PATTERNS = (
    "ssh -o", "scp ", "rsync ", "psexec", "smbclient", "wmic ",
    "curl -o", "curl -o", "wget ", "ftp -n", "/tmp/donotcry",
    "donotcry", "ransome", "lateral",
)

_EXECUTION_PATTERNS = (
    "/bin/sh", "/bin/bash", "python ", "python3 ", "perl ", "ruby ",
    "powershell", "cmd.exe", "mshta.exe", "wscript", "cscript",
    "dpkg -i", "rpm -i", "/tmp/",
)


def _parse_ts(val: Any) -> datetime | None:
    if isinstance(val, datetime):
        return val
    if not val or not isinstance(val, str):
        return None
    try:
        cleaned = val.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


class KillChainCollector:
    """Extracts 5-phase MITRE findings and AttackStage candidate objects from telemetry."""

    def collect(
        self,
        events: list[dict[str, Any]],
        seed_host: str | None = None,
    ) -> tuple[dict[str, KillChainPhase], list[AttackStage]]:
        stages: list[AttackStage] = []

        phases: dict[str, KillChainPhase] = {
            "initial_access": KillChainPhase(name="Initial Access"),
            "execution": KillChainPhase(name="Execution"),
            "credential_access": KillChainPhase(name="Credential Access"),
            "discovery": KillChainPhase(name="Discovery"),
            "lateral_movement": KillChainPhase(name="Lateral Movement"),
        }

        # Track per-phase evidence
        ia_candidates: dict[str, float] = {}
        ia_vectors: dict[str, int] = {}
        failed_auth_count = 0
        success_auth_users: set[str] = set()

        for event in events:
            raw = event.get("raw") or event
            text = (
                str(raw.get("description") or "")
                + " " + str(raw.get("full_log") or "")
                + " " + str(raw.get("command_line") or "")
                + " " + str(raw.get("alert_name") or "")
                + " " + str(event.get("event_type") or "")
            ).lower()

            host = str(event.get("host") or event.get("hostname") or raw.get("agent_host") or seed_host or "unknown")
            score = float(event.get("score") or event.get("risk_score") or raw.get("score_hint") or 10.0)
            ts = _parse_ts(event.get("timestamp") or raw.get("time") or raw.get("@timestamp"))

            # 1. Initial Access Evaluation
            if any(p in text for p in _BRUTE_FORCE_PATTERNS):
                failed_auth_count += 1
                ia_vectors["brute_force"] = ia_vectors.get("brute_force", 0) + 1
                ia_candidates[f"host:{host}"] = ia_candidates.get(f"host:{host}", 0.0) + 5.0
                src_ip = event.get("src_ip") or raw.get("src_ip")
                if src_ip:
                    ia_candidates[f"ip:{src_ip}"] = ia_candidates.get(f"ip:{src_ip}", 0.0) + 5.0

            if any(p in text for p in _VALID_ACCOUNT_PATTERNS):
                user = raw.get("user") or raw.get("dst_user") or raw.get("username")
                if user:
                    success_auth_users.add(str(user))
                    ia_candidates[f"user:{user}"] = ia_candidates.get(f"user:{user}", 0.0) + 20.0
                ia_vectors["valid_account"] = ia_vectors.get("valid_account", 0) + 1

            # 2. Execution Evaluation
            if any(p in text for p in _EXECUTION_PATTERNS) or "exec" in str(event.get("event_type", "")):
                cmd = raw.get("command_line") or raw.get("cmd") or raw.get("process_name") or "exec"
                proc_name = str(cmd).split()[0] if cmd else "process"
                if score >= 30.0:
                    phases["execution"].mitre_techniques.extend(["T1059", "T1204"])
                    phases["execution"].findings.append(f"Host {host}: executed '{cmd}' (score={score})")
                    stages.append(
                        AttackStage(
                            host=host,
                            artifact=proc_name,
                            score=score,
                            timestamp=ts,
                            source="event",
                            description=f"Executed {cmd}",
                            mitre_techniques=["T1059"],
                        )
                    )

            # 3. Credential Access Evaluation
            if any(p in text for p in _CRED_ACCESS_PATTERNS):
                phases["credential_access"].status = "confirmed"
                phases["credential_access"].vector = "os_credential_dump"
                phases["credential_access"].confidence = max(phases["credential_access"].confidence, 0.90)
                phases["credential_access"].mitre_techniques.extend(["T1003", "T1552"])
                phases["credential_access"].findings.append(f"Host {host}: credential access observed targeting '{text[:100]}'")
                stages.append(
                    AttackStage(
                        host=host,
                        artifact="credential_dump",
                        score=max(score, 85.0),
                        timestamp=ts,
                        source="detection",
                        description="Credential harvesting/dumping activity",
                        mitre_techniques=["T1003"],
                    )
                )

            # 4. Discovery Evaluation
            if any(p in text for p in _DISCOVERY_PATTERNS):
                phases["discovery"].status = "confirmed"
                phases["discovery"].confidence = max(phases["discovery"].confidence, 0.80)
                phases["discovery"].mitre_techniques.extend(["T1087", "T1046", "T1083"])
                phases["discovery"].findings.append(f"Host {host}: discovery sweep '{text[:100]}'")

            # 5. Lateral Movement Evaluation
            if any(p in text for p in _LATERAL_MOVEMENT_PATTERNS):
                phases["lateral_movement"].status = "confirmed"
                vector = "tool_transfer" if ("curl" in text or "wget" in text or "donotcry" in text) else "ssh"
                phases["lateral_movement"].vector = vector
                phases["lateral_movement"].confidence = max(phases["lateral_movement"].confidence, 0.85)
                phases["lateral_movement"].mitre_techniques.extend(["T1021", "T1105"])
                target_detail = text[:80].strip()
                phases["lateral_movement"].findings.append(
                    f"Host {host}: lateral movement ({vector}) targeting '{target_detail}'"
                )
                artifact_name = "donotcry" if "donotcry" in text else ("tool_transfer" if vector == "tool_transfer" else "lateral_ssh")
                stages.append(
                    AttackStage(
                        host=host,
                        artifact=artifact_name,
                        score=max(score, 75.0),
                        timestamp=ts,
                        source="detection",
                        description=f"Lateral movement via {vector}",
                        mitre_techniques=["T1105" if vector == "tool_transfer" else "T1021"],
                    )
                )

        # Finalize Initial Access Phase
        if failed_auth_count > 0:
            top_vector = max(ia_vectors.items(), key=lambda x: x[1])[0] if ia_vectors else "brute_force"
            phases["initial_access"].status = "confirmed"
            phases["initial_access"].vector = top_vector
            phases["initial_access"].confidence = min(0.60 + (failed_auth_count * 0.05), 1.0)
            phases["initial_access"].mitre_techniques = ["T1110", "T1078"]
            phases["initial_access"].findings.append(
                f"Initial access: {failed_auth_count} failed auth attempts observed. Corroborated with successful login for users: {list(success_auth_users)}"
            )

            # Format candidates
            candidates_list = [
                {"entity": entity, "score": round(sc, 2), "vector": top_vector}
                for entity, sc in sorted(ia_candidates.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            phases["initial_access"].candidates = candidates_list
            if candidates_list:
                phases["initial_access"].entry_entity = candidates_list[0]["entity"]
                if "host:" in candidates_list[0]["entity"]:
                    phases["initial_access"].entry_host = candidates_list[0]["entity"].split("host:")[1]

        # Deduplicate techniques across phases
        for p in phases.values():
            p.mitre_techniques = sorted(list(set(p.mitre_techniques)))
            if p.findings and p.status == "unconfirmed":
                p.status = "likely"
                p.confidence = max(p.confidence, 0.70)

        # Ensure at least one initial stage if seed host is provided
        if not stages and seed_host:
            stages.append(
                AttackStage(
                    host=seed_host,
                    artifact="alert_origin",
                    score=50.0,
                    source="event",
                    description="Initial alert origin host",
                )
            )

        return phases, stages
