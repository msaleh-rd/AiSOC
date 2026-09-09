"""Unit tests for the Investigation Swarm (v8 P3)."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.swarm.complexity import assess_complexity
from app.swarm.debate import hold_debate
from app.swarm.hypotheses import HYPOTHESES
from app.swarm.swarm import run_swarm_llm, run_swarm_sync

RANSOMWARE = {
    "alert_summary": "Ransomware encrypting files on host; vssadmin deleted shadow copies; ransom note dropped",
    "raw": "lockbit .lockbit lateral movement via smb, credential dump with mimikatz",
    "techniques": ["T1486", "T1490", "T1021.002", "T1003"],
    "iocs": {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "file_hash": "abc"},
    "hostname": "WIN-FIN-DB01",
    "username": "svc-backup",
}

BENIGN = {
    "alert_summary": "Scheduled backup completed nominal",
    "raw": "veeam backup finished, service account svc-backup, maintenance window",
    "techniques": [],
}


def test_complexity_gate_fires_on_multi_entity_multi_technique():
    a = assess_complexity(RANSOMWARE)
    assert a.is_complex
    assert a.entity_count >= 3
    assert a.technique_count >= 3
    # A simple benign alert should not trip the swarm.
    assert not assess_complexity(BENIGN).is_complex


def test_complexity_gate_fires_on_tactic_diversity_alone():
    """Two techniques spanning distinct MITRE tactics (Initial Access +
    Impact) should trip the complexity gate even with few entities/techniques,
    since spanning multiple kill-chain stages signals a multi-stage attack."""
    signal = {
        "alert_summary": "Exploit of public-facing app followed by data destruction",
        "techniques": ["T1190", "T1486"],  # TA0001 (Initial Access), TA0040 (Impact)
    }
    a = assess_complexity(signal)
    assert a.tactic_count == 2
    assert a.is_complex
    assert any("tactic" in r for r in a.reasons)

    # A single technique (single tactic) alone should not trip on tactics.
    single_tactic = {"alert_summary": "isolated event", "techniques": ["T1486"]}
    a2 = assess_complexity(single_tactic)
    assert a2.tactic_count == 1
    assert not a2.is_complex


def test_swarm_fans_out_and_scores_hypotheses():
    results = run_swarm_sync(RANSOMWARE)
    assert len(results) == min(5, len(HYPOTHESES))
    by_key = {r.key: r for r in results}
    # Ransomware + lateral-movement should score well; the FP-backup hypothesis low.
    assert by_key["ransomware_staging"].support_score > 0.3
    assert by_key["lateral_movement"].support_score > 0.3
    assert by_key["false_positive_backup"].support_score <= by_key["ransomware_staging"].support_score
    # Cost is bounded per agent.
    assert all(r.tokens_spent <= 1500 for r in results)


def test_debate_ranks_ransomware_first_on_a_ransomware_alert():
    results = run_swarm_sync(RANSOMWARE)
    outcome = hold_debate(results)
    assert outcome.winner is not None
    assert outcome.winner.key in {"ransomware_staging", "lateral_movement", "c2_beacon"}
    assert not outcome.winner.benign
    # Ranked list is sorted by score descending with bounded confidence.
    scores = [h.score for h in outcome.ranked]
    assert scores == sorted(scores, reverse=True)
    assert 0.05 <= outcome.winner.confidence <= 0.95
    # Ledger payload is a first-class debate step.
    assert outcome.ledger_payload["step_type"] == "debate"
    assert len(outcome.ledger_payload["hypotheses"]) == len(results)


def test_memory_prior_can_shift_the_ranking():
    results = run_swarm_sync(BENIGN)
    # With a strong prior that this signature is historically a backup FP,
    # the benign hypothesis should be competitive.
    outcome = hold_debate(results, memory_priors={"false_positive_backup": 1.0})
    keys = [h.key for h in outcome.ranked]
    assert keys[0] == "false_positive_backup"


@respx.mock
async def test_llm_swarm_reports_real_token_usage_not_a_fake_constant(monkeypatch: pytest.MonkeyPatch):
    """Regression test: tokens_spent must reflect the real LiteLLM ``usage``
    field from the single shared generation call, distributed across the
    hypotheses it produced — not a fabricated per-agent constant."""
    monkeypatch.setenv("AISOC_SWARM_LLM_ENABLED", "1")
    monkeypatch.setenv("LITELLM_URL", "http://litellm-test:4000")

    respx.post("http://litellm-test:4000/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"hypotheses": ['
                                '{"hypothesis": "ransomware staging", "supporting_techniques": ["T1486"], '
                                '"contradicting_keywords": [], "is_benign": false, "confidence": 0.8},'
                                '{"hypothesis": "false positive backup", "supporting_techniques": [], '
                                '"contradicting_keywords": ["backup"], "is_benign": true, "confidence": 0.3}'
                                "]}"
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 300, "completion_tokens": 100, "total_tokens": 400},
            },
        )
    )

    results = await run_swarm_llm(RANSOMWARE, max_agents=5)

    assert len(results) == 2
    total_tokens = sum(r.tokens_spent for r in results)
    # The real total from the mocked usage field, not len(results) * 500.
    assert total_tokens == 400
    assert all(r.tokens_spent > 0 for r in results)
