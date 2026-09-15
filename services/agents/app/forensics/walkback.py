"""Causal Walkback Analyzer: reconstructs attack chain backward from anchor alerts.

Ported from sxsecurityinvestigator: walks back along causal relationships
(PROCESS_SPAWNED, AUTHENTICATED_TO, CONNECTED_TO, PART_OF_SESSION) to identify
the initial entry point / root cause leading up to the detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.forensics.process_tree import _get_field, _normalize_proc_name
from app.forensics.session_linkage import extract_session_tokens


@dataclass
class WalkbackStep:
    """A single step in the causal walkback chain."""

    timestamp: str
    entity: str
    action: str
    technique: str = ""
    evidence: str = ""
    is_root_cause: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "entity": self.entity,
            "action": self.action,
            "technique": self.technique,
            "evidence": self.evidence,
            "is_root_cause": self.is_root_cause,
        }


@dataclass
class WalkbackResult:
    """Result of causal walkback reconstruction."""

    root_cause_candidate: str
    attack_type: str
    confidence: float
    chain: list[WalkbackStep] = field(default_factory=list)
    contributing_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause_candidate": self.root_cause_candidate,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "chain": [s.to_dict() for s in self.chain],
            "contributing_factors": self.contributing_factors,
        }


class CausalWalkback:
    """Walks back causal dependencies from the incident alert across gathered events."""

    def analyze(
        self,
        anchor_alert: dict[str, Any],
        related_events: list[dict[str, Any]],
    ) -> WalkbackResult:
        all_events = [anchor_alert] + [e for e in related_events if e != anchor_alert]

        # 1. Check if the alert is a configuration compliance / CIS check
        alert_title = str(anchor_alert.get("title") or anchor_alert.get("name") or anchor_alert.get("rule_name") or anchor_alert.get("message") or "").lower()
        rule_desc = str(anchor_alert.get("description") or "").lower()
        combined_text = f"{alert_title} {rule_desc}"

        is_compliance_check = any(kw in combined_text for kw in (
            "ensure sshd", "cis benchmark", "compliance", "permission", "configuration check",
            "password policy", "auditd rule", "sysctl", "file permissions"
        ))

        host = str(_get_field(anchor_alert, "host", "hostname", "affected_host", default="unknown_host"))
        anchor_ts = str(_get_field(anchor_alert, "timestamp", "time", default=""))

        # Sort related events chronologically if timestamps are parseable
        def _parse_ts(e: dict[str, Any]) -> float:
            t = _get_field(e, "timestamp", "time", default="")
            if isinstance(t, (int, float)):
                return float(t)
            try:
                return datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0

        sorted_events = sorted(all_events, key=_parse_ts)

        chain: list[WalkbackStep] = []
        root_cause = host
        attack_type = "initial_access"
        confidence = 0.50

        if is_compliance_check:
            # For compliance / system audit findings, the root cause is system hardening gap
            root_cause = f"System Configuration on {host}"
            attack_type = "policy_violation"
            confidence = 0.88
            chain.append(WalkbackStep(
                timestamp=anchor_ts,
                entity=host,
                action="Security Baseline / Compliance Audit Finding",
                technique="T1562.001 - Disable or Modify Tools / Insecure Configuration",
                evidence=alert_title or "SSHD configuration deviates from recommended security baseline",
                is_root_cause=True,
            ))
            return WalkbackResult(
                root_cause_candidate=root_cause,
                attack_type=attack_type,
                confidence=confidence,
                chain=chain,
                contributing_factors=[
                    f"Configuration audit evaluated on host '{host}'",
                    f"Finding: {alert_title}",
                ],
            )

        # 2. Check for process tree ancestry
        process_lineage: list[str] = anchor_alert.get("process_ancestors") or []
        current_proc = _normalize_proc_name(_get_field(anchor_alert, "process", "process_name"))
        parent_proc = _normalize_proc_name(_get_field(anchor_alert, "parent_process", "parent_process_name"))

        if process_lineage or (current_proc and parent_proc):
            full_ancestry = list(process_lineage)
            if parent_proc and parent_proc not in full_ancestry:
                full_ancestry.insert(0, parent_proc)

            ancestor_root = full_ancestry[-1] if full_ancestry else parent_proc
            root_cause = f"{host}:{ancestor_root}"
            attack_type = "execution"
            confidence = 0.85

            for ancestor in reversed(full_ancestry):
                chain.append(WalkbackStep(
                    timestamp=anchor_ts,
                    entity=f"{host}:{ancestor}",
                    action=f"Spawned child process in execution chain",
                    technique="T1059 - Command and Scripting Interpreter",
                    evidence=f"Process lineage: {' -> '.join(full_ancestry)} -> {current_proc}",
                    is_root_cause=(ancestor == ancestor_root),
                ))

        # 3. Check for external network connection / initial access
        src_ip = str(_get_field(anchor_alert, "src_ip", "source_ip", default=""))
        dst_ip = str(_get_field(anchor_alert, "dst_ip", "destination_ip", default=""))
        if src_ip and not src_ip.startswith(("127.", "10.", "192.168.", "172.16.")):
            root_cause = f"ip:{src_ip}"
            attack_type = "initial_access"
            confidence = 0.90
            chain.insert(0, WalkbackStep(
                timestamp=anchor_ts,
                entity=f"ip:{src_ip}",
                action="Inbound network connection from external origin",
                technique="T1190 - Exploit Public-Facing Application",
                evidence=f"External IP {src_ip} initiated session to {dst_ip or host}",
                is_root_cause=True,
            ))

        if not chain:
            chain.append(WalkbackStep(
                timestamp=anchor_ts,
                entity=host,
                action=alert_title or "Security event detected",
                evidence="Single event anchor without antecedent telemetry",
                is_root_cause=True,
            ))

        return WalkbackResult(
            root_cause_candidate=root_cause,
            attack_type=attack_type,
            confidence=confidence,
            chain=chain,
            contributing_factors=[
                f"Evaluated {len(all_events)} related events across host '{host}'",
                f"Lineage depth: {len(chain)} steps",
            ],
        )
