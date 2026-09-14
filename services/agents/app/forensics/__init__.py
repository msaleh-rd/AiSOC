"""AiSOC Deterministic Forensics Package.

High-throughput, zero-LLM forensic analysis ported from sxsecurityinvestigator.
Provides timeline collapsing, MITRE 5-phase kill-chain evaluation, and attack-chain sequencing.
"""

from __future__ import annotations

from app.forensics.attack_chain_builder import AttackChainBuilder
from app.forensics.deterministic_report import DeterministicReportGenerator
from app.forensics.engine import ForensicsEngine
from app.forensics.kill_chain_collector import KillChainCollector
from app.forensics.models import (
    AttackStage,
    ForensicInvestigationPackage,
    KillChainPhase,
    TimelineEntry,
)
from app.forensics.timeline_collapser import TimelineCollapser

__all__ = [
    "AttackChainBuilder",
    "AttackStage",
    "DeterministicReportGenerator",
    "ForensicInvestigationPackage",
    "ForensicsEngine",
    "KillChainPhase",
    "KillChainCollector",
    "TimelineCollapser",
    "TimelineEntry",
]
