"""Unit tests for RCA LLM narrative synthesis."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.rca.synthesis import _build_prompt, synthesize_rca_narrative


def test_build_prompt_structure():
    rca = {
        "root_cause_entity": "host:10.0.0.5",
        "target_entity": "host:10.0.0.12",
        "confidence": 0.85,
        "confidence_level": "high",
        "attack_type": "lateral_movement",
        "supporting_evidence_count": 4,
        "contradicting_evidence_count": 0,
        "estimated_blast_radius": 3,
        "remediation_complexity": "moderate",
        "temporal_sequence": [
            {"timestamp": "2026-09-14T10:00:00Z", "entity": "host:10.0.0.5", "action": "port scan"},
            {"timestamp": "2026-09-14T10:05:00Z", "entity": "host:10.0.0.12", "action": "unauthorized smb login"},
        ],
        "pagerank_scores": {
            "host:10.0.0.5": 0.65,
            "host:10.0.0.12": 0.25,
            "user:admin": 0.10,
        },
    }
    prompt = _build_prompt(rca, "Potential intrusion on database server")
    assert "host:10.0.0.5" in prompt
    assert "host:10.0.0.12" in prompt
    assert "lateral_movement" in prompt
    assert "Potential intrusion on database server" in prompt
    assert "port scan" in prompt


@respx.mock
async def test_synthesize_rca_narrative_success(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LITELLM_URL", "http://litellm-test:4000")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    respx.post("http://litellm-test:4000/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "Host 10.0.0.5 initiated unauthorized reconnaissance. It then pivoted to 10.0.0.12 via SMB. The evidence strongly supports 10.0.0.5 as the root cause."
                        }
                    }
                ]
            },
        )
    )

    rca = {
        "root_cause_entity": "host:10.0.0.5",
        "target_entity": "host:10.0.0.12",
        "confidence": 0.85,
    }
    narrative = await synthesize_rca_narrative(rca, "Lateral movement alert")
    assert narrative is not None
    assert "10.0.0.5" in narrative
    assert "root cause" in narrative


@respx.mock
async def test_synthesize_rca_narrative_failure_returns_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LITELLM_URL", "http://litellm-test:4000")

    respx.post("http://litellm-test:4000/v1/chat/completions").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    rca = {"root_cause_entity": "host:10.0.0.5"}
    narrative = await synthesize_rca_narrative(rca, "Alert")
    assert narrative is None


async def test_synthesize_rca_narrative_empty_rca_returns_none():
    assert await synthesize_rca_narrative({}, "Alert") is None
