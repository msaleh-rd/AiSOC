"""The competing hypotheses the swarm evaluates.

Each hypothesis carries supporting/contradicting signal keywords and the MITRE
techniques that corroborate it. A hypothesis agent scores its hypothesis against
an alert deterministically (an LLM can enrich this, but the deterministic floor
is what CI gates).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Hypothesis:
    key: str
    label: str
    supports_keywords: frozenset[str]
    contradicts_keywords: frozenset[str] = frozenset()
    techniques: frozenset[str] = frozenset()
    # Whether this hypothesis is a "benign" explanation (competes with the malicious ones).
    benign: bool = False
    # Prior belief in [0, 1]. Static hypotheses use a neutral 0.5; the
    # LLM-generated path sets this from the model's own stated confidence so
    # scoring is grounded in the generator's assessment rather than a flat
    # constant that lets zero-evidence hypotheses tie and win by list order.
    prior: float = 0.5


HYPOTHESES: list[Hypothesis] = [
    Hypothesis(
        key="ransomware_staging",
        label="Ransomware staging",
        supports_keywords=frozenset({"ransomware", "encrypt", "shadow copy", "vssadmin", "lockbit", ".lockbit", "ransom note"}),
        contradicts_keywords=frozenset({"backup completed", "scheduled backup"}),
        techniques=frozenset({"T1486", "T1490"}),
    ),
    Hypothesis(
        key="insider_exfil",
        label="Insider exfiltration",
        supports_keywords=frozenset({"exfiltration", "large file", "usb", "personal email", "download", "staging", "off-hours"}),
        techniques=frozenset({"T1048", "T1567", "T1052"}),
    ),
    Hypothesis(
        key="lateral_movement",
        label="Lateral movement / intrusion",
        supports_keywords=frozenset({"lateral movement", "smb", "psexec", "credential dump", "mimikatz", "pass the hash", "rdp"}),
        techniques=frozenset({"T1021", "T1021.002", "T1003", "T1550"}),
    ),
    Hypothesis(
        key="c2_beacon",
        label="C2 beacon / active intrusion",
        supports_keywords=frozenset({"c2", "beacon", "cobalt strike", "command and control", "dns tunneling", "jitter"}),
        techniques=frozenset({"T1071", "T1573", "T1071.004"}),
    ),
    Hypothesis(
        key="false_positive_backup",
        label="False positive (backup / maintenance job)",
        supports_keywords=frozenset({"backup", "veeam", "maintenance window", "scheduled", "nominal", "service account", "svc-backup"}),
        contradicts_keywords=frozenset({"ransom note", "exfiltration to unknown", "mimikatz"}),
        benign=True,
    ),
    Hypothesis(
        key="network_recon",
        label="Network reconnaissance / sniffing",
        supports_keywords=frozenset({"promiscuous", "sniffing", "packet capture", "tcpdump", "wireshark", "port scan", "nmap", "arp spoof", "network scan"}),
        contradicts_keywords=frozenset({"span port", "network sensor", "monitoring appliance"}),
        techniques=frozenset({"T1040", "T1046", "T1595", "T1557"}),
    ),
    Hypothesis(
        key="benign_security_tooling",
        label="Benign security tooling / monitoring agent",
        supports_keywords=frozenset({"suricata", "zeek", "ids sensor", "network sensor", "span port", "monitoring agent", "wazuh agent", "vulnerability scan", "authorized scan"}),
        contradicts_keywords=frozenset({"unknown process", "unauthorized", "mimikatz", "ransom note"}),
        benign=True,
    ),
]
