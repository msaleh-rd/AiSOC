#!/usr/bin/env python3
"""End-to-end verification and live demonstration script for the 5 ported capabilities.

Usage::

    .venv/Scripts/python.exe -m app.scripts.verify_all_features

This script exercises:
  1. Compounding Memory & Outcome Distillation (app.memory.distillation)
  2. 7-Stage Alert Noise Compression (app.compression)
  3. Causal Graph & PageRank Root Cause Analysis (app.rca)
  4. Investigation Swarm & Hypothesis Debate (app.swarm)
  5. ReAct Autonomous Supervisor & LangGraph Workflow (app.orchestrator.supervisor, app.graph.workflow)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import json
import os
import sys
from uuid import uuid4

# Ensure local test/verification can initialize chat models without live credentials
os.environ.setdefault("OPENAI_API_KEY", "mock-eval-key")
os.environ.setdefault("OTEL_EXPORTER", "console")


def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


# ---------------------------------------------------------------------------
# 1. Compounding Memory Verification
# ---------------------------------------------------------------------------
async def verify_compounding_memory() -> None:
    banner("1. Compounding Memory & Outcome Distillation")
    from app.memory.distillation import CompoundingMemory

    memory = CompoundingMemory()
    tenant = f"tenant-{uuid4().hex[:6]}"
    sig = "edr:crowdstrike:t1059:powershell_encoded_command"

    print(f"[+] Recording triage outcomes for signature: '{sig}'")
    # Record 8 confirmed incidents and 2 false positives
    for i in range(8):
        await memory.record_verdict(
            tenant_id=tenant,
            signature=sig,
            verdict="true_positive",
            confidence=0.92,
            investigation_id=f"inv-tp-{i+1}",
        )
    for i in range(2):
        await memory.record_verdict(
            tenant_id=tenant,
            signature=sig,
            verdict="false_positive",
            confidence=0.85,
            investigation_id=f"inv-fp-{i+1}",
        )

    # Distill
    print("[+] Running background distillation...")
    report = await memory.distill(tenant)
    print(f"    Signatures processed: {report.signatures_processed}")
    prior = report.priors.get(sig)
    assert prior is not None, "Prior must be generated"

    print(f"    Total recorded: {prior.total_count}")
    print(f"    False positives: {prior.false_positive_count} ({prior.false_positive_rate:.1%})")
    print(f"    Prior confidence: {prior.prior_confidence:.2f}")
    print(f"    Cached exemplar investigations: {prior.exemplar_investigation_ids}")

    # Query Bayesian adjustment
    adj = memory.get_adjustment(sig, current_confidence=0.80)
    print(f"[+] Bayesian adjustment on new alert (input confidence 0.80) -> {adj:.3f}")
    assert adj > 0.80, "High true-positive historical rate should boost confidence"

    exemplars = memory.get_exemplars(sig)
    print(f"[+] Retrieved {len(exemplars)} exemplar cases for prompt context")
    print("[OK] Compounding Memory verified successfully!")


# ---------------------------------------------------------------------------
# 2. 7-Stage Noise Compression Verification
# ---------------------------------------------------------------------------
def verify_compression_pipeline() -> list[dict]:
    banner("2. 7-Stage Alert Noise Compression Pipeline")
    from app.compression.models import CorrelatedEvent, MitreTechnique
    from app.compression.pipeline import CompressionPipeline

    pipeline = CompressionPipeline()
    now = datetime.utcnow()

    # Generate realistic raw events: duplicates, outside window, lateral movement, etc.
    events = [
        # Outside 24h window
        CorrelatedEvent(
            timestamp=now - timedelta(hours=36),
            entity_id="host-web-01",
            event_type="system",
            action="file_read",
            risk_score=0.1,
            confidence=0.5,
        ),
        # Normal behavior
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=45),
            entity_id="host-web-01",
            event_type="heartbeat",
            action="routine_heartbeat",
            risk_score=0.05,
            confidence=0.5,
        ),
        # Duplicates of noisy log
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=30),
            entity_id="host-web-01",
            event_type="network",
            action="port_scan_probe",
            risk_score=0.6,
            confidence=0.7,
        ),
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=29),
            entity_id="host-web-01",
            event_type="network",
            action="port_scan_probe",
            risk_score=0.6,
            confidence=0.7,
        ),
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=28),
            entity_id="host-web-01",
            event_type="network",
            action="port_scan_probe",
            risk_score=0.6,
            confidence=0.7,
        ),
        # Initial access / lateral movement chain (tight temporal sequence < 5 min)
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=6),
            entity_id="user-svc-admin",
            event_type="process",
            action="powershell_download_c2",
            risk_score=0.95,
            confidence=0.9,
            mitre_technique=MitreTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
        ),
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=4),
            entity_id="host-web-01",
            event_type="process",
            action="psexec_remote_execution",
            risk_score=0.92,
            confidence=0.9,
            mitre_technique=MitreTechnique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ),
        CorrelatedEvent(
            timestamp=now - timedelta(minutes=2),
            entity_id="host-db-primary",
            event_type="database",
            action="database_dump_exfiltration",
            risk_score=0.98,
            confidence=0.95,
            mitre_technique=MitreTechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        ),
    ]

    print(f"[+] Input: {len(events)} raw correlated events")
    pkg = pipeline.compress(events, investigation_id="inv-demo-01")

    print(f"[+] Output: {pkg.compressed_event_count} events ({pkg.compression_ratio:.1f}x compression)")
    print("[+] Stage Metrics:")
    for idx, m in enumerate(pkg.stage_metrics, 1):
        dropped = m.input_count - m.output_count
        print(f"    Stage {idx} ({m.name:22s}): {m.input_count:2d} -> {m.output_count:2d} (dropped {dropped:2d}, -{m.reduction_pct:.1%})")

    print("\n[+] Retained High-Fidelity Forensic Events:")
    for e in pkg.events:
        tech = e.mitre_technique.technique_id if e.mitre_technique else "none"
        print(f"    [{e.timestamp.strftime('%H:%M:%S')}] {e.entity_id:18s} -> {e.action:30s} (risk: {e.risk_score:.2f}, MITRE: {tech})")

    assert pkg.compressed_event_count <= pkg.original_event_count
    print("[OK] 7-Stage Noise Compression verified successfully!")
    return [e.to_dict() for e in pkg.events]



# ---------------------------------------------------------------------------
# 3. Causal Graph + PageRank RCA Verification
# ---------------------------------------------------------------------------
def verify_rca_engine(compressed_dicts: list[dict]) -> dict:
    banner("3. Causal Graph + PageRank Root Cause Analysis")
    from app.compression.stages import normalise_event
    from app.rca.causal_graph import CausalGraphBuilder
    from app.rca.pagerank_scorer import PageRankRCA

    events = [normalise_event(d) for d in compressed_dicts]
    builder = CausalGraphBuilder()
    graph = builder.build_from_events(events)

    print(f"[+] Causal Graph built: {graph.number_of_nodes()} entities, {graph.number_of_edges()} causal links")
    for u, v, data in graph.edges(data=True):
        print(f"    {u} -> {v}  (weight: {data.get('weight', 1.0):.2f})")

    rca = PageRankRCA()
    target_symptom = "host-db-primary"
    result = rca.analyze(graph, target_entity=target_symptom, events=events)

    print(f"\n[+] Symptom Entity: {target_symptom}")
    print(f"[+] Identified Root Cause: '{result.root_cause_entity}' (confidence: {result.confidence:.2f}, level: {result.confidence_level})")
    print(f"[+] Attack Classification: {result.attack_type}")
    print(f"[+] Blast Radius: {result.estimated_blast_radius} descendant entities affected")
    print(f"[+] Remediation Complexity: {result.remediation_complexity}")
    print("[+] PageRank Entity Distribution:")
    for entity, score in sorted(result.pagerank_scores.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {entity:20s}: {score:.4f}")

    assert result.root_cause_entity in ("user-svc-admin", "host-web-01")
    print("[OK] Causal Graph RCA verified successfully!")
    return result.to_dict()


# ---------------------------------------------------------------------------
# 4. Investigation Swarm Verification
# ---------------------------------------------------------------------------
async def verify_investigation_swarm() -> None:
    banner("4. Investigation Swarm (Competing Hypotheses Debate)")
    from app.swarm import hold_debate, run_swarm

    signal = {
        "classification": "Ransomware Lateral Movement",
        "severity": "critical",
        "alert_summary": "PsExec execution and mass shadow copy deletion across domain controller and database servers",
        "techniques": ["T1021.002", "T1490", "T1059.001"],
        "entities": ["host-web-01", "host-db-primary", "user-svc-admin"],
    }

    print("[+] Fanning out competing hypothesis agents across signal...")
    results = await run_swarm(signal, max_agents=5)

    print(f"[+] Evaluated {len(results)} competing hypotheses:")
    for r in results:
        kind = "BENIGN" if r.benign else "MALICIOUS"
        print(f"    - [{kind:9s}] {r.label:25s} score: {r.support_score:.2f} | hits: {r.technique_hits}")

    outcome = hold_debate(results)
    assert outcome.winner is not None, "Swarm debate must yield a winner"

    print(f"\n[+] Swarm Debate Winner: '{outcome.winner.label}'")
    print(f"    Confidence: {outcome.winner.confidence:.2f}")
    if len(outcome.ranked) > 1:
        runner_up = outcome.ranked[1]
        print(f"    Runner-up: '{runner_up.label}' (score: {runner_up.score:.2f})")
    print("[OK] Investigation Swarm verified successfully!")


# ---------------------------------------------------------------------------
# 5. ReAct Autonomous Supervisor Loop Verification
# ---------------------------------------------------------------------------
async def verify_react_supervisor(compressed_events: list[dict], rca_findings: dict) -> None:
    banner("5. ReAct Autonomous Supervisor Loop & Supervised LangGraph Workflow")
    from app.graph.workflow import get_supervised_graph
    from app.models.state import AgentStatus, InvestigationState
    from app.orchestrator.supervisor import ReActSupervisor

    # Step A: Test supervisor reasoning directly
    print("[+] Step A: Verifying supervisor decision logic on blackboard state...")
    state = InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="Compromised service account performing lateral movement and database exfiltration",
        severity="high",
        entities=[
            {"type": "user", "id": "user-svc-admin"},
            {"type": "host", "id": "host-web-01"},
            {"type": "host", "id": "host-db-primary"},
        ],
        mitre_mappings=["T1059.001", "T1021.002", "T1048"],
    )

    supervisor = ReActSupervisor()

    # Iteration 1: Initial state (entities populated, no compressed events) -> supervisor chooses compress_events
    d1 = await supervisor.decide(state)
    print(f"    Cycle 1 Decision: action='{d1.action}', goal='{d1.specific_goal}'")
    assert d1.action in ("gather_evidence", "compress_events")

    # Simulate evidence gathered & compressed events populated
    state.add_finding("Extracted 3 endpoints and 2 user accounts")
    state.compressed_events = compressed_events

    # Iteration 2: With compressed events (rca_conf < 0.70) -> supervisor chooses perform_rca
    d2 = await supervisor.decide(state)
    print(f"    Cycle 2 Decision: action='{d2.action}', goal='{d2.specific_goal}'")
    assert d2.action in ("perform_rca", "run_swarm", "run_specialist")

    # Simulate RCA populated (confidence 0.88 >= 0.75)
    state.rca_findings = rca_findings
    state.add_finding("RCA confirmed root cause as host-web-01")

    # Iteration 3: With RCA and evidence -> finalize
    d3 = await supervisor.decide(state)
    print(f"    Cycle 3 Decision: action='{d3.action}', goal='{d3.specific_goal}'")
    assert d3.action == "finalize_response"

    # Step B: Test the compiled LangGraph workflow execution
    print("\n[+] Step B: Executing compiled Supervised Graph workflow...")
    graph = get_supervised_graph()
    initial_dict = state.to_dict()

    final_output = await graph.ainvoke(initial_dict)

    print(f"    Execution status: {final_output.get('status')}")
    print(f"    Total iterations: {final_output.get('iteration_count')}")
    print(f"    Action history: {final_output.get('action_counts')}")
    print("    Recorded Findings in blackboard:")
    for f in final_output.get("findings", [])[-4:]:
        print(f"      * {f}")

    assert final_output.get("status") == AgentStatus.COMPLETED.value
    print("[OK] ReAct Autonomous Supervisor Loop verified successfully!")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
async def main() -> None:
    banner("AiSOC Advanced Investigation Capabilities — Full Verification Suite")
    print("Starting automated verification across all 5 ported capabilities...\n")

    try:
        await verify_compounding_memory()
        compressed_events = verify_compression_pipeline()
        rca_findings = verify_rca_engine(compressed_events)
        await verify_investigation_swarm()
        await verify_react_supervisor(compressed_events, rca_findings)

        banner("ALL 5 CAPABILITIES VERIFIED AND OPERATIONAL")
        print("\nSUMMARY:")
        print("  1. Compounding Memory:             PASS")
        print("  2. 7-Stage Noise Compression:      PASS")
        print("  3. NetworkX PageRank RCA:          PASS")
        print("  4. Investigation Swarm Debate:     PASS")
        print("  5. ReAct Autonomous Supervisor:    PASS")
        print("=" * 78)
    except Exception as exc:
        print(f"\n[FAIL] Verification encountered an error: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
