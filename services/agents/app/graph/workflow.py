"""
LangGraph workflow: wires Auto-Triage → Triage → Enrichment → Investigation
→ Attack-Path agents.

Auto-triage runs first.  If the LLM classifies the alert as FP/benign with
confidence above the auto-close threshold the graph terminates early.
Otherwise the alert flows through the full manual pipeline, ending with the
graph-aware Attack-Path agent that walks Neo4j to compute blast radius.
"""

from __future__ import annotations

import asyncio

import structlog
from langgraph.graph import END, StateGraph

from app.agents.attack_path_agent import run_attack_path
from app.agents.auto_triage_agent import AutoTriageError, run_auto_triage
from app.agents.enrichment_agent import run_enrichment
from app.agents.investigation_agent import run_investigation
from app.agents.triage_agent import run_triage
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


def _state_dict(state: InvestigationState) -> dict:
    return state.to_dict()


def _from_dict(d: dict) -> InvestigationState:
    return InvestigationState.model_validate(d)


# ---- Node wrappers (LangGraph uses dict state, we wrap our Pydantic model) ----


async def auto_triage_node(state: dict) -> dict:
    s = _from_dict(state)
    try:
        s = await run_auto_triage(s)
    except AutoTriageError as exc:
        # LLM/parse failure (issue #571): never terminate on a null verdict —
        # escalate through the full pipeline (deterministic triage runs next).
        logger.warning("graph.auto_triage_failed_escalating", error=str(exc), incident_id=str(s.incident_id))
        s.add_finding(f"Auto-triage LLM unavailable ({exc}) — escalating to full pipeline")
        if s.status is AgentStatus.COMPLETED:
            s.status = AgentStatus.RUNNING
    return s.to_dict()


async def triage_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_triage(s)
    return s.to_dict()


async def enrichment_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_enrichment(s)
    return s.to_dict()


async def investigation_node(state: dict) -> dict:
    s = _from_dict(state)
    # Deterministic Forensics Engine (Track A) — runs unconditionally
    try:
        from app.forensics import ForensicsEngine  # noqa: PLC0415

        engine = ForensicsEngine()
        pkg = engine.analyze(
            events=s.compressed_events or [],
            incident_id=str(s.incident_id),
            entities=s.entities,
            raw_alert=s.raw_alert,
        )
        s.forensic_package = pkg.to_dict()
        if pkg.attack_chain:
            chain_str = " → ".join(pkg.attack_chain)
            s.add_finding(f"Forensic attack chain: {chain_str}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("workflow.forensics_failed", error=str(exc))

    s = await run_investigation(s)
    return s.to_dict()


async def attack_path_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_attack_path(s)
    return s.to_dict()


def _should_continue(state: dict) -> str:
    """Conditional edge: stop if max iterations reached or status is terminal."""
    s = _from_dict(state)
    if s.iteration_count >= s.max_iterations:
        return "end"
    if s.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED):
        return "end"
    return "continue"


def _after_auto_triage(state: dict) -> str:
    """Route after auto-triage: auto-closed alerts go to END, others continue."""
    s = _from_dict(state)
    if s.status == AgentStatus.COMPLETED:
        return "end"
    return "continue"


def build_investigation_graph() -> StateGraph:
    """Build and compile the investigation workflow graph.

    Flow:
        auto_triage ─┬─ (high-confidence FP/benign) ──► END
                      └─ (else) ──► triage ──► enrichment ──► investigation
                                          ──► attack_path ──► END
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)

    graph.set_entry_point("auto_triage")

    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "triage"},
    )
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)

    return graph.compile()


def build_escalation_graph() -> StateGraph:
    """The post-triage escalation pipeline (issue #569).

    Shares the SAME node implementations as the full graph but skips the
    auto-triage entry node — used by the Kafka auto-triage worker, which has
    already produced a governed verdict, to route escalated alerts (TP /
    low-confidence / needs_review) through enrichment → investigation →
    attack-path without re-triaging.

    Flow: triage ──► enrichment ──► investigation ──► attack_path ──► END
    """
    graph = StateGraph(dict)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)
    graph.set_entry_point("triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)
    return graph.compile()


# Module-level compiled graphs (singletons)
investigation_graph = build_investigation_graph()
escalation_graph = build_escalation_graph()


# ---------------------------------------------------------------------------
# Supervised investigation graph (v8.1 — ReAct supervisor loop)
# ---------------------------------------------------------------------------
#
# Feature flag: AISOC_AGENT_SUPERVISED_MODE (default off).
#
# Topology:
#     START → auto_triage → supervisor ←──────────────────────┐
#                              │                               │
#                              ├─► gather_evidence ───────────►│
#                              ├─► run_specialist ────────────►│
#                              ├─► compress_events ───────────►│
#                              ├─► run_swarm ─────────────────►│
#                              ├─► perform_rca ───────────────►│
#                              └─► finalize_response ───────► END


async def supervisor_node(state: dict) -> dict:
    """Supervisor node: observe state → decide next action."""
    from app.orchestrator.supervisor import ReActSupervisor  # noqa: PLC0415

    s = _from_dict(state)
    supervisor = ReActSupervisor()
    decision = await supervisor.decide(s)

    # Record the decision in the audit trail.
    s.supervisor_history.append(decision.to_dict())

    # Update action counter.
    counts = dict(s.action_counts or {})
    counts[decision.action] = counts.get(decision.action, 0) + 1
    s.action_counts = counts
    s.iteration_count += 1

    # Store the chosen action in a routing key for the conditional edge.
    d = s.to_dict()
    d["_supervisor_action"] = decision.action
    d["_supervisor_goal"] = decision.specific_goal
    d["_supervisor_entities"] = decision.target_entities
    return d


async def gather_evidence_node(state: dict) -> dict:
    """Gather forensic evidence from entities and the platform alert store."""
    s = _from_dict(state)
    s = await run_enrichment(s)
    s.add_finding("Evidence gathering completed via enrichment agent")

    # Pull related alerts from the platform datastore so compression / RCA /
    # swarm operate on real sibling telemetry instead of a single event.
    try:
        from app.evidence import collect_related_alerts  # noqa: PLC0415

        raw = s.raw_alert or {}
        hostnames = {str(h) for h in (raw.get("affected_hosts") or []) if h}
        if raw.get("hostname"):
            hostnames.add(str(raw["hostname"]))
        device = raw.get("device")
        if isinstance(device, dict) and device.get("name"):
            hostnames.add(str(device["name"]))
        ips = {str(i) for i in (raw.get("affected_ips") or []) if i}
        for key in ("src_ip", "dst_ip"):
            if raw.get(key):
                ips.add(str(raw[key]))
        users = {str(u) for u in (raw.get("affected_users") or []) if u}
        for entity in s.entities:
            if isinstance(entity, dict) and entity.get("value"):
                etype = entity.get("entity_type")
                if etype == "host":
                    hostnames.add(str(entity["value"]))
                elif etype == "ip":
                    ips.add(str(entity["value"]))
                elif etype == "user":
                    users.add(str(entity["value"]))

        related = await collect_related_alerts(
            tenant_id=str(s.tenant_id),
            hostnames=sorted(hostnames),
            ips=sorted(ips),
            users=sorted(users),
            exclude_alert_id=str(s.incident_id),
        )
        if related:
            seen_ids = {
                e.get("alert_id")
                for e in s.entities
                if isinstance(e, dict) and e.get("alert_id")
            }
            added = 0
            for event in related:
                if event.get("alert_id") not in seen_ids:
                    seen_ids.add(event.get("alert_id"))
                    s.entities.append(event)
                    added += 1
            s.add_finding(
                f"Platform evidence: {added} related alerts collected for "
                f"{len(hostnames)} host(s), {len(ips)} IP(s), {len(users)} user(s)"
            )
        else:
            s.add_finding(
                "Platform evidence: no related alerts found for the involved entities"
            )
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"Platform evidence collection unavailable: {exc}")
        logger.warning("supervised.platform_evidence_failed", error=str(exc))

    # Run deterministic ForensicsEngine (Track A) over gathered evidence
    try:
        from app.forensics import ForensicsEngine  # noqa: PLC0415

        engine = ForensicsEngine()
        pkg = engine.analyze(
            events=s.compressed_events or [],
            incident_id=str(s.incident_id),
            entities=s.entities,
            raw_alert=s.raw_alert,
        )
        s.forensic_package = pkg.to_dict()
        if pkg.attack_chain:
            chain_str = " → ".join(pkg.attack_chain)
            s.add_finding(f"Forensic attack chain: {chain_str}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("supervised.gather_evidence_forensics_failed", error=str(exc))

    return s.to_dict()


async def compress_events_node(state: dict) -> dict:
    """Run the 7-stage noise compression pipeline."""
    s = _from_dict(state)
    try:
        from app.compression.pipeline import CompressionPipeline  # noqa: PLC0415

        pipeline = CompressionPipeline()
        # Compress raw alert data + findings into a compressed package.
        raw_events = []
        if s.raw_alert:
            raw_events.append(s.raw_alert)
        for entity in s.entities:
            if isinstance(entity, dict):
                raw_events.append(entity)

        if raw_events:
            package = pipeline.compress(raw_events, investigation_id=str(s.incident_id))
            s.compressed_events = [e.to_dict() for e in package.events]
            s.add_finding(
                f"Compression: {package.original_event_count} → "
                f"{package.compressed_event_count} events "
                f"({package.compression_ratio:.1f}x reduction)"
            )
        else:
            s.add_finding("Compression: no raw events to compress")
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"Compression failed: {exc}")
        logger.warning("supervised.compress_failed", error=str(exc))
    return s.to_dict()


async def run_swarm_node(state: dict) -> dict:
    """Run the competing hypothesis swarm."""
    s = _from_dict(state)
    try:
        from app.swarm import hold_debate, run_swarm_llm  # noqa: PLC0415

        signal = {
            "alert_summary": s.alert_summary,
            "techniques": s.mitre_mappings,
            "entities": s.entities,
            **(s.raw_alert or {}),
        }
        results = await run_swarm_llm(signal)
        outcome = hold_debate(results)
        if outcome.winner:
            evidence_bits = list(outcome.winner.evidence)[:6]
            evidence_note = (
                f" — evidence: {', '.join(evidence_bits)}" if evidence_bits else ""
            )
            s.add_finding(
                f"Swarm winner: {outcome.winner.label} "
                f"(confidence: {outcome.winner.confidence:.2f}){evidence_note}"
            )
        else:
            s.add_finding(
                "Swarm: no hypothesis gained evidentiary support — no verdict asserted"
            )
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"Swarm failed: {exc}")
        logger.warning("supervised.swarm_failed", error=str(exc))
    return s.to_dict()


async def perform_rca_node(state: dict) -> dict:
    """Run PageRank root cause analysis."""
    s = _from_dict(state)
    try:
        from app.compression.models import CorrelatedEvent  # noqa: PLC0415
        from app.compression.stages import normalise_event  # noqa: PLC0415
        from app.rca.causal_graph import CausalGraphBuilder  # noqa: PLC0415
        from app.rca.pagerank_scorer import PageRankRCA  # noqa: PLC0415

        # Build events from compressed_events or entities.
        events = [normalise_event(e) for e in (s.compressed_events or s.entities or [])]
        # The RCA target must be the entity actually experiencing the alert
        # (e.g. the affected host/user from the original alert), not an
        # arbitrary event's entity — picking events[0] could select an
        # attacker IP or unrelated entity depending on event ordering.
        if s.raw_alert:
            target = normalise_event(s.raw_alert).entity_id
        elif events:
            target = events[0].entity_id
        else:
            target = "unknown"

        builder = CausalGraphBuilder()
        graph = builder.build_from_events(events)

        rca = PageRankRCA()
        result = rca.analyze(graph, target, events)
        s.rca_findings = result.to_dict()

        # sxsecurityinvestigator: Causal Walkback & Process Ancestry validation
        try:
            from app.forensics.walkback import CausalWalkback
            from app.forensics.process_tree import build_process_trees

            all_raw = []
            if s.raw_alert:
                all_raw.append(s.raw_alert)
            if s.compressed_events:
                all_raw.extend(s.compressed_events)

            build_process_trees(all_raw)
            walkback = CausalWalkback()
            wb_result = walkback.analyze(s.raw_alert or {}, s.compressed_events or [])
            if wb_result.confidence > result.confidence or not graph.edges:
                s.rca_findings["root_cause_entity"] = wb_result.root_cause_candidate
                s.rca_findings["attack_type"] = wb_result.attack_type
                s.rca_findings["confidence"] = wb_result.confidence
                s.rca_findings["walkback_chain"] = [step.to_dict() for step in wb_result.chain]
                s.rca_findings["contributing_factors"] = wb_result.contributing_factors
        except Exception as exc:  # noqa: BLE001
            logger.warning("supervised.walkback_analysis_failed", error=str(exc))

        s.add_finding(
            f"RCA: root cause is '{s.rca_findings.get('root_cause_entity')}' "
            f"(confidence: {s.rca_findings.get('confidence', 0.0):.2f}, "
            f"attack type: {s.rca_findings.get('attack_type', 'unknown')})"
        )

        # Best-effort LLM synthesis of the causal candidates into an
        # analyst-readable narrative. The PageRank result above remains
        # authoritative — a synthesis failure never fails the investigation.
        try:
            from app.rca.synthesis import synthesize_rca_narrative  # noqa: PLC0415

            narrative = await synthesize_rca_narrative(s.rca_findings, s.alert_summary)
            if narrative:
                s.rca_findings["narrative"] = narrative
                s.add_finding(f"RCA narrative: {narrative}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("supervised.rca_synthesis_failed", error=str(exc))
    except Exception as exc:  # noqa: BLE001
        s.add_finding(f"RCA failed: {exc}")
        logger.warning("supervised.rca_failed", error=str(exc))
    return s.to_dict()


async def parallel_analysis_node(state: dict) -> dict:
    """Run the three analysis tracks concurrently, then fuse their verdicts.

    Track A — kill-chain phase hunts (deterministic, anchor-chained; ported
    from sxsecurityinvestigator's orchestration layer).
    Track B — competing-hypothesis swarm (LLM).
    Track C — root cause analysis (PageRank + causal walkback + narrative).

    Fusion rules keep the output honest:
    * compliance/SCA noise is tagged first and excluded from hypothesis text,
    * a swarm winner with <2 evidence signals needs kill-chain corroboration
      or it is reported as an uncorroborated hypothesis,
    * an RCA attack_type with no supporting phase verdict is labeled
      uncorroborated.
    """
    s = _from_dict(state)

    # Tag compliance noise before any track consumes the corpus.
    try:
        from app.forensics.noise import tag_noise  # noqa: PLC0415

        noise_count, signal_count = tag_noise(s.entities)
        if noise_count:
            s.add_finding(
                f"Noise filter: {noise_count} compliance/maintenance event(s) "
                f"tagged (kept for context, excluded from hypothesis matching); "
                f"{signal_count} signal event(s) remain"
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("supervised.noise_tagging_failed", error=str(exc))

    base_findings = set(s.findings)
    base_state = s.to_dict()

    async def _hunt_track():
        from app.forensics.phase_hunts import run_phase_hunts  # noqa: PLC0415

        return await run_phase_hunts(s.entities, raw_alert=s.raw_alert)

    async def _swarm_track():
        from app.swarm import hold_debate, run_swarm_llm  # noqa: PLC0415

        signal = {
            "alert_summary": s.alert_summary,
            "techniques": s.mitre_mappings,
            "entities": s.entities,
            **(s.raw_alert or {}),
        }
        results = await run_swarm_llm(signal)
        return hold_debate(results)

    hunts, swarm_outcome, rca_state = await asyncio.gather(
        _hunt_track(),
        _swarm_track(),
        perform_rca_node(dict(base_state)),
        return_exceptions=True,
    )

    # ── Track A: kill-chain phase verdicts ──
    phase_verdicts: dict = {}
    if isinstance(hunts, BaseException):
        s.add_finding(f"Phase hunts failed: {hunts}")
        logger.warning("supervised.phase_hunts_failed", error=str(hunts))
    else:
        from app.forensics.phase_hunts import summarize_phase_verdicts  # noqa: PLC0415

        phase_verdicts = hunts
        pkg = dict(s.forensic_package or {})
        pkg["kill_chain_phases"] = {k: v.to_dict() for k, v in hunts.items()}
        s.forensic_package = pkg
        s.add_finding(summarize_phase_verdicts(hunts))

    # ── Track C: RCA (merged before swarm so fusion can inspect it) ──
    if isinstance(rca_state, BaseException):
        s.add_finding(f"RCA failed: {rca_state}")
        logger.warning("supervised.parallel_rca_failed", error=str(rca_state))
    else:
        s.rca_findings = rca_state.get("rca_findings") or {}
        for f in rca_state.get("findings") or []:
            if f not in base_findings:
                s.add_finding(f)
        # An attack_type with no confirmed/likely phase verdict is a guess.
        at = str(s.rca_findings.get("attack_type") or "")
        pv = phase_verdicts.get(at)
        if at and at != "unknown" and (
            pv is None or pv.status not in ("confirmed", "likely")
        ):
            s.rca_findings["attack_type"] = f"{at} (uncorroborated)"

    # ── Track B: swarm + corroboration fusion ──
    if isinstance(swarm_outcome, BaseException):
        s.add_finding(f"Swarm failed: {swarm_outcome}")
        logger.warning("supervised.parallel_swarm_failed", error=str(swarm_outcome))
    else:
        winner = swarm_outcome.winner
        if winner is None:
            s.add_finding(
                "Swarm: no hypothesis gained evidentiary support — no verdict asserted"
            )
        else:
            winner_techs = {
                e.split("technique:", 1)[1]
                for e in winner.evidence
                if e.startswith("technique:")
            }
            corroborated = any(
                v.status in ("confirmed", "likely")
                and bool(winner_techs & set(v.mitre_techniques))
                for v in phase_verdicts.values()
            )
            weak = len(winner.evidence) < 2
            if weak and not corroborated:
                s.add_finding(
                    f"Swarm: top hypothesis '{winner.label}' has only "
                    f"{len(winner.evidence)} evidence signal(s) and no "
                    f"kill-chain corroboration — uncorroborated, not asserted"
                )
            else:
                evidence_bits = list(winner.evidence)[:6]
                note = (
                    f" — evidence: {', '.join(evidence_bits)}" if evidence_bits else ""
                )
                corr = " (kill-chain corroborated)" if corroborated else ""
                s.add_finding(
                    f"Swarm winner: {winner.label} "
                    f"(confidence: {winner.confidence:.2f}){note}{corr}"
                )

    return s.to_dict()


async def finalize_response_node(state: dict) -> dict:
    """Generate final response plan and close the investigation."""
    s = _from_dict(state)
    s.status = AgentStatus.COMPLETED
    if s.forensic_package and s.forensic_package.get("attack_chain"):
        if not s.rca_findings:
            s.rca_findings = {}
        s.rca_findings["attack_chain"] = s.forensic_package["attack_chain"]
    s.add_finding("Investigation finalized by supervisor")

    d = s.to_dict()

    # Per-phase cards for the console (Recon / Forensic / Response).
    # Shapes match CaseWorkspace.tsx:
    #   recon.{summary, iocs[{type,value}], mitre_techniques[]}
    #   forensic.{summary, root_cause_hypothesis, confidence, ...package}
    #   responder.{summary, recommended_actions[{action,rationale}], risk_level}
    iocs = [
        {"type": i.get("ioc_type", "ioc"), "value": i.get("value", "")}
        for i in (s.threat_intel.get("pending_iocs") or [])
        if isinstance(i, dict) and i.get("value")
    ]
    related_alerts = sum(
        1 for e in (s.entities or []) if isinstance(e, dict) and e.get("alert_id")
    )
    hosts = sorted(
        {
            str(e.get("value"))
            for e in (s.entities or [])
            if isinstance(e, dict) and e.get("entity_type") == "host" and e.get("value")
        }
    )
    recon_bits = [f"{len(iocs)} IOC(s) extracted"]
    if related_alerts:
        recon_bits.append(f"{related_alerts} related platform alert(s) collected")
    if hosts:
        recon_bits.append(f"host(s): {', '.join(hosts[:3])}")
    d["recon"] = {
        "summary": "; ".join(recon_bits) + ".",
        "iocs": iocs[:10],
        "mitre_techniques": list(s.mitre_mappings or [])[:10],
    }

    rca = s.rca_findings or {}
    forensic = dict(s.forensic_package or {})
    forensic_bits: list[str] = []
    for prefix in ("Platform evidence:", "Compression:", "Noise filter:", "Kill chain:", "Swarm"):
        note = next((f for f in s.findings if f.startswith(prefix)), None)
        if note:
            forensic_bits.append(note)
    forensic["summary"] = (
        " · ".join(forensic_bits)
        or "No forensic evidence was collected for this run."
    )
    if rca.get("narrative"):
        forensic["root_cause_hypothesis"] = str(rca["narrative"])
    elif rca.get("root_cause_entity"):
        forensic["root_cause_hypothesis"] = (
            f"Root cause: {rca['root_cause_entity']} "
            f"(attack type: {rca.get('attack_type', 'unknown')})"
        )
    if isinstance(rca.get("confidence"), (int, float)):
        forensic["confidence"] = float(rca["confidence"])
    d["forensic"] = forensic

    # Responder risk follows the verdict, not raw confidence: a benign
    # auto-close at 0.92 confidence is LOW risk, not high.
    verdict = (s.verdict or "needs_review").lower()
    if "benign" in verdict or "false_positive" in verdict:
        risk = "low"
    elif "true_positive" in verdict or "malicious" in verdict:
        risk = "high"
    else:
        risk = "medium"
    rationale = next(
        (
            f.removeprefix("Auto-triage rationale: ")
            for f in s.findings
            if f.startswith("Auto-triage rationale:")
        ),
        "",
    )
    responder_summary = (
        f"Verdict: {s.verdict or 'needs_review'} (confidence {s.confidence:.0%})."
    )
    if rationale:
        responder_summary += f" {rationale}"
    raw_actions = [
        a.to_dict() if hasattr(a, "to_dict") else a
        for a in (s.proposed_actions or [])
    ]
    actions = [
        {
            "action": a.get("description") or a.get("action_type", ""),
            "rationale": a.get("rationale", ""),
        }
        for a in raw_actions[:6]
        if isinstance(a, dict)
    ]
    d["responder"] = {
        "summary": responder_summary[:600],
        "risk_level": risk,
        "recommended_actions": actions,
    }

    try:
        from app.orchestrator.report import render_router_report

        report_md, report_html = render_router_report(s)
        if s.forensic_package and s.forensic_package.get("markdown_report"):
            forensic_md = s.forensic_package["markdown_report"]
            if forensic_md and forensic_md not in report_md:
                report_md = f"{report_md}\n\n---\n\n{forensic_md}"
        d["report_md"] = report_md
        d["report_html"] = report_html
    except Exception as exc:  # noqa: BLE001
        logger.warning("finalize_response.report_render_failed", error=str(exc))
    return d


def _supervisor_route(state: dict) -> str:
    """Route based on the supervisor's chosen action."""
    action = state.get("_supervisor_action", "finalize_response")
    if action == "finalize_response":
        return "finalize"
    if action in ("gather_evidence", "run_specialist"):
        return "evidence"
    if action == "compress_events":
        return "compress"
    if action == "run_swarm":
        return "swarm"
    if action == "perform_rca":
        return "rca"
    if action == "parallel_analysis":
        return "parallel"
    return "finalize"


def build_supervised_graph() -> StateGraph:
    """Build the ReAct supervised investigation graph.

    The supervisor node decides the next action; after each action the graph
    re-enters the supervisor for another observe→reason→act cycle.
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("gather_evidence", gather_evidence_node)
    graph.add_node("compress_events", compress_events_node)
    graph.add_node("run_swarm", run_swarm_node)
    graph.add_node("perform_rca", perform_rca_node)
    graph.add_node("parallel_analysis", parallel_analysis_node)
    graph.add_node("finalize_response", finalize_response_node)

    graph.set_entry_point("auto_triage")

    # After auto-triage: if auto-closed → END, else → supervisor.
    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "supervisor"},
    )

    # Supervisor routes to one of the action nodes.
    graph.add_conditional_edges(
        "supervisor",
        _supervisor_route,
        {
            "evidence": "gather_evidence",
            "compress": "compress_events",
            "swarm": "run_swarm",
            "rca": "perform_rca",
            "parallel": "parallel_analysis",
            "finalize": "finalize_response",
        },
    )

    # All action nodes loop back to supervisor (except finalize → END).
    graph.add_edge("gather_evidence", "supervisor")
    graph.add_edge("compress_events", "supervisor")
    graph.add_edge("run_swarm", "supervisor")
    graph.add_edge("perform_rca", "supervisor")
    graph.add_edge("parallel_analysis", "supervisor")
    graph.add_edge("finalize_response", END)

    return graph.compile()


# Lazy-init: only compile the supervised graph when the feature flag is on.
_supervised_graph_cache = None


def get_supervised_graph():
    """Return the supervised investigation graph (compiled on first call)."""
    global _supervised_graph_cache  # noqa: PLW0603
    if _supervised_graph_cache is None:
        _supervised_graph_cache = build_supervised_graph()
    return _supervised_graph_cache

