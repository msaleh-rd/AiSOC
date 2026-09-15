"""
ForensicAgent — Phase 2 of the investigator pipeline.

Responsibilities:
  • Build a chronological event timeline from enrichment data + raw alert
  • Hypothesise root cause and blast radius
  • Identify forensic artefacts (file paths, registry keys, network artefacts)
  • Produce a confidence-scored forensic summary
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model, resolve_model_alias
from app.prompt_serialization import summarize_structure_for_llm

from .bundle_prompt import format_bundle_prompt_append
from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import ForensicFindings, InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ForensicAgent of an AI Security Operations Centre.
Given a security alert and its enrichment data, produce:
1. A chronological timeline of events (at most 15 entries).
2. A list of forensic artefacts (file paths, registry keys, network indicators).
3. A root-cause hypothesis (one sentence).
4. An estimated blast radius (what systems/data were or could be affected).
5. A confidence score (0.0–1.0) for your analysis.

Respond ONLY with a JSON object:
{
  "timeline": [{"ts": "ISO8601 or relative", "event": "...", "src": "..."}],
  "artefacts": ["C:\\\\path\\\\to\\\\file.exe", "HKCU\\\\..."],
  "root_cause_hypothesis": "...",
  "blast_radius": "...",
  "confidence": 0.75,
  "summary": "Two-sentence forensic summary."
}
"""


async def _llm_forensic(state: InvestigatorState, pkg: Any = None) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        model = resolve_model_alias("investigation")
        llm = make_chat_model("investigation", temperature=0)

        # Defence-in-depth: alert_summary, recon.summary, and the enrichment cache
        # can all carry attacker-controlled strings (banners, dark-web excerpts,
        # WHOIS values, etc.). Sanitise them and wrap the enrichment blob in an
        # explicit <UNTRUSTED_DATA> envelope so the system prompt stays trusted.
        safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
        safe_recon = sanitize_text(state.recon.summary, max_len=2_000)
        safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
        enrichment_blob = summarize_structure_for_llm(
            dict(list(state.enrichment_cache.items())[:10]),
            label="enrichment_cache",
            max_lines=40,
            max_depth=2,
        )

        chain_section = ""
        if pkg and getattr(pkg, "attack_chain", None):
            chain_section = f"Deterministic attack chain:\n{' → '.join(pkg.attack_chain)}\n\n"

        prompt = (
            f"Alert summary:\n{safe_summary}\n\n"
            f"{chain_section}"
            f"Recon findings:\n{safe_recon}\n"
            f"MITRE techniques: {safe_mitre}\n\n"
            f"Enrichment data (sample):\n{enrichment_blob}"
        )
        bundle_append = format_bundle_prompt_append(state.context_bundle)
        if bundle_append:
            prompt = f"{prompt}\n\n{bundle_append}"

        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        prompt_hash = state.log_llm_prompt(
            agent="ForensicAgent",
            prompt=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            model=model,
            purpose="forensic: timeline, artefacts, root cause, blast radius",
        )

        response = await safe_ainvoke(llm, messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Tier 1.6: record cost telemetry on the active CostTracker.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="forensic",
            tool="llm.forensic",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        state.log_llm_response(
            agent="ForensicAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict) and "timeline" in parsed:
                return parsed
    except Exception as exc:  # noqa: BLE001
        logger.warning("forensic_agent llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ForensicAgent",
            f"LLM call failed: {exc}",
        )

    # Fallback to deterministic forensics package (Track A)
    state.log_decision(
        agent="ForensicAgent",
        decision="deterministic_fallback",
        reason="LLM unavailable or returned malformed output; using deterministic forensic package",
        confidence=0.85 if pkg else 0.1,
        alternatives=["llm_extraction"],
    )
    fallback_timeline = [t.to_dict() for t in pkg.timeline] if pkg else []
    fallback_artefacts = (
        [s.split(":")[1] for s in pkg.attack_chain if ":" in s and not s.startswith("http")]
        if pkg else []
    )
    fallback_root_cause = (
        f"Attack chain initiated via {pkg.attack_chain[0]}"
        if (pkg and pkg.attack_chain)
        else "Investigation analyzed telemetry."
    )
    fallback_blast = (
        f"{len(pkg.attack_chain)} attack stages across {pkg.incident_host}."
        if pkg else "Unknown — manual review required."
    )
    return {
        "timeline": fallback_timeline,
        "artefacts": fallback_artefacts,
        "root_cause_hypothesis": fallback_root_cause,
        "blast_radius": fallback_blast,
        "confidence": 0.85 if pkg else 0.1,
        "summary": (
            f"Deterministic analysis identified {len(pkg.attack_chain)} stages across {pkg.incident_host}."
            if pkg else "Automated forensic analysis was not available."
        ),
    }


async def run_forensic(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("forensic_agent.start", case_id=state.case_id)

    # Run deterministic forensics engine (Track A) unconditionally
    from app.forensics import ForensicsEngine  # noqa: PLC0415

    engine = ForensicsEngine()
    pkg = engine.analyze(
        events=state.context_bundle.get("events", []) if state.context_bundle else [],
        incident_id=state.case_id,
        entities=[{"value": ioc.get("value"), "type": ioc.get("type")} for ioc in state.recon.iocs],
        raw_alert=state.raw_alert or {"alert_name": state.alert_summary},
    )

    llm_result = await _llm_forensic(state, pkg=pkg)

    timeline_items = llm_result.get("timeline", [])
    if not timeline_items and pkg.timeline:
        timeline_items = [t.to_dict() for t in pkg.timeline]

    state.forensic = ForensicFindings(
        timeline=timeline_items,
        artefacts=llm_result.get("artefacts", [])
        or [s.split(":")[1] for s in pkg.attack_chain if ":" in s and not s.startswith("http")],
        attack_chain=pkg.attack_chain,
        kill_chain_phases={k: v.to_dict() for k, v in pkg.kill_chain_phases.items()},
        forensic_package=pkg.to_dict(),
        root_cause_hypothesis=llm_result.get("root_cause_hypothesis", ""),
        blast_radius=llm_result.get("blast_radius", ""),
        confidence=float(llm_result.get("confidence", 0.0)) or 0.85,
        summary=llm_result.get("summary", ""),
    )

    # Cite each forensic artefact as evidence for downstream replay
    for artefact in state.forensic.artefacts[:50]:
        state.log_evidence(
            agent="ForensicAgent",
            evidence_kind="artefact",
            ref=str(artefact),
            weight=state.forensic.confidence,
        )

    if state.forensic.root_cause_hypothesis:
        state.log_decision(
            agent="ForensicAgent",
            decision="root_cause_hypothesis",
            reason=state.forensic.root_cause_hypothesis,
            confidence=state.forensic.confidence,
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.FORENSIC,
        "ForensicAgent",
        f"Timeline: {len(state.forensic.timeline)} events, confidence {state.forensic.confidence:.0%}",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.recon.model_dump()),
        output_hash=sha256_of(state.forensic.model_dump()),
    )
    state.iteration += 1
    logger.info("forensic_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
