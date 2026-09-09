"""Fan out competing hypothesis agents in parallel, each with a cost budget.

Each hypothesis agent independently "gathers evidence" (deterministically here:
scanning the alert text + techniques for supporting/contradicting signal) and
returns an evidence bundle + a raw support score. Agents run concurrently
(``asyncio.gather``); each is capped by a per-agent token/cost budget so the
swarm's total spend stays bounded and predictable.

LLM-backed mode (v8.1)
======================

When ``AISOC_SWARM_LLM_ENABLED=1`` (default off), ``run_swarm_llm()``
generates 3–5 hypotheses via structured LLM output instead of using the
static ``HYPOTHESES`` list. Each generated hypothesis is then scored
concurrently against the signal using evidence overlap + technique
corroboration + contradiction penalty.

The deterministic path remains the **default** and the **fallback** when
the LLM is unavailable.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.swarm.hypotheses import HYPOTHESES, Hypothesis

logger = structlog.get_logger()

# A per-agent budget (tokens). Deterministic agents don't spend, but the budget
# is threaded through so the LLM-backed variant is bounded and the swarm's
# aggregate cost is (num_agents * per_agent_budget) — the ceiling CI checks.
DEFAULT_PER_AGENT_TOKEN_BUDGET = 1500

_LLM_FLAG = "AISOC_SWARM_LLM_ENABLED"


def _is_llm_enabled() -> bool:
    raw = os.getenv(_LLM_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


@dataclass(frozen=True)
class HypothesisResult:
    key: str
    label: str
    benign: bool
    support_score: float  # 0–1, how well the evidence supports this hypothesis
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    technique_hits: list[str] = field(default_factory=list)
    tokens_spent: int = 0


def _signal_text(signal: dict) -> str:
    parts = [str(signal.get("alert_summary", "")), str(signal.get("title", "")), str(signal.get("raw", ""))]
    return " ".join(parts).lower()


def _evaluate(hypothesis: Hypothesis, signal: dict, budget: int) -> HypothesisResult:
    text = _signal_text(signal)
    techniques = {t.upper() for t in (signal.get("techniques") or signal.get("mitre_techniques") or [])}

    evidence = sorted(kw for kw in hypothesis.supports_keywords if kw in text)
    contradictions = sorted(kw for kw in hypothesis.contradicts_keywords if kw in text)
    tech_hits = sorted(techniques & {t.upper() for t in hypothesis.techniques})

    # Deterministic support score: keyword coverage + technique corroboration,
    # minus contradictions. Bounded to [0, 1].
    kw_component = min(len(evidence) * 0.25, 0.6)
    tech_component = min(len(tech_hits) * 0.3, 0.5)
    penalty = min(len(contradictions) * 0.3, 0.6)
    score = max(0.0, min(1.0, kw_component + tech_component - penalty))

    return HypothesisResult(
        key=hypothesis.key,
        label=hypothesis.label,
        benign=hypothesis.benign,
        support_score=round(score, 4),
        evidence=evidence,
        contradictions=contradictions,
        technique_hits=tech_hits,
        tokens_spent=min(budget, 200),  # deterministic agents are cheap
    )


async def _agent(hypothesis: Hypothesis, signal: dict, budget: int) -> HypothesisResult:
    # Yield to the loop so the fan-out is genuinely concurrent.
    await asyncio.sleep(0)
    return _evaluate(hypothesis, signal, budget)


async def run_swarm(
    signal: dict,
    *,
    hypotheses: list[Hypothesis] | None = None,
    max_agents: int = 5,
    per_agent_budget: int = DEFAULT_PER_AGENT_TOKEN_BUDGET,
) -> list[HypothesisResult]:
    """Fan out up to ``max_agents`` hypothesis agents in parallel."""
    chosen = (hypotheses or HYPOTHESES)[:max_agents]
    results = await asyncio.gather(*[_agent(h, signal, per_agent_budget) for h in chosen])
    return list(results)


def run_swarm_sync(signal: dict, **kwargs) -> list[HypothesisResult]:
    """Synchronous convenience wrapper (for tests / non-async callers)."""
    return asyncio.run(run_swarm(signal, **kwargs))


# ---------------------------------------------------------------------------
# LLM-backed hypothesis generation (v8.1)
# ---------------------------------------------------------------------------


async def _generate_hypotheses_llm(
    signal: dict,
    *,
    max_hypotheses: int = 5,
) -> list[Hypothesis]:
    """Generate competing hypotheses from the signal context using LiteLLM.

    Falls back to the static HYPOTHESES list if the LLM is unavailable.
    """
    entities_summary = ""
    entities = signal.get("entities") or []
    if entities:
        entity_parts = []
        for e in entities[:20]:
            if isinstance(e, dict):
                entity_parts.append(f"{e.get('type', '?')}:{e.get('id', '?')}")
            else:
                entity_parts.append(str(e))
        entities_summary = ", ".join(entity_parts)

    classification = signal.get("classification", signal.get("alert_summary", "unknown alert"))
    severity = signal.get("severity", "unknown")
    techniques_str = ", ".join(signal.get("techniques") or signal.get("mitre_techniques") or [])

    prompt = (
        "You are a senior SOC investigator. Given the investigation context below, "
        f"generate {max_hypotheses} distinct, mutually exclusive competing hypotheses "
        "for what is really happening (e.g. ransomware staging, lateral movement "
        "from a compromised peer, insider threat, false positive / legitimate "
        "admin activity). For each hypothesis, respond with a JSON array where "
        "each object has: hypothesis (string), supporting_techniques (list of "
        "MITRE ATT&CK technique IDs), contradicting_keywords (list of strings), "
        "is_benign (boolean), confidence (float 0-1).\n\n"
        f"Classification: {classification}\n"
        f"Severity: {severity}\n"
        f"Entities: {entities_summary or 'none identified'}\n"
        f"MITRE Techniques: {techniques_str or 'none'}\n"
        f"Alert Summary: {signal.get('alert_summary', '')}\n"
    )

    try:
        import json

        import httpx

        litellm_url = os.getenv("LITELLM_URL", "http://litellm:4000")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{litellm_url}/v1/chat/completions",
                json={
                    "model": os.getenv("AISOC_SWARM_MODEL", "gpt-4o-mini"),
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.7,
                    "max_tokens": 1500,
                    "response_format": {"type": "json_object"},
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)

            # Accept either {"hypotheses": [...]} or a bare list.
            items = parsed if isinstance(parsed, list) else parsed.get("hypotheses", [])

            generated: list[Hypothesis] = []
            for item in items[:max_hypotheses]:
                key = str(item.get("hypothesis", "unknown")).lower().replace(" ", "_")[:40]
                generated.append(Hypothesis(
                    key=key,
                    label=str(item.get("hypothesis", "Unknown")),
                    supports_keywords=frozenset(),  # LLM-generated; no keyword matching
                    contradicts_keywords=frozenset(item.get("contradicting_keywords", [])),
                    techniques=frozenset(item.get("supporting_techniques", [])),
                    benign=bool(item.get("is_benign", False)),
                ))

            if generated:
                logger.info("swarm.llm_hypotheses_generated", count=len(generated))
                return generated

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "swarm.llm_generation_failed_using_fallback",
            error=str(exc).replace("\r", "").replace("\n", " ")[:200],
        )

    # Fallback to static hypotheses.
    return HYPOTHESES[:max_hypotheses]


async def _score_hypothesis_llm(
    hypothesis: Hypothesis,
    signal: dict,
    budget: int,
) -> HypothesisResult:
    """Score an LLM-generated hypothesis against the signal.

    Uses evidence overlap + technique corroboration + contradiction penalty.
    Same deterministic scoring as the static path — the LLM only generates
    the hypotheses, it doesn't score them.
    """
    await asyncio.sleep(0)  # yield for concurrency

    text = _signal_text(signal)
    observed_techniques = {
        t.upper()
        for t in (signal.get("techniques") or signal.get("mitre_techniques") or [])
    }
    supporting = {t.upper() for t in hypothesis.techniques}
    overlap = len(observed_techniques & supporting)
    total_supporting = max(len(supporting), 1)
    evidence_overlap = overlap / total_supporting

    # Check contradictions in the signal text.
    contradictions = sorted(kw for kw in hypothesis.contradicts_keywords if kw.lower() in text)
    contradiction_penalty = min(0.3, len(contradictions) * 0.1)

    # Combined score.
    score = max(0.0, min(1.0, 0.6 * evidence_overlap + 0.4 * 0.5 - contradiction_penalty))

    return HypothesisResult(
        key=hypothesis.key,
        label=hypothesis.label,
        benign=hypothesis.benign,
        support_score=round(score, 4),
        evidence=[f"technique:{t}" for t in sorted(observed_techniques & supporting)],
        contradictions=contradictions,
        technique_hits=sorted(observed_techniques & supporting),
        tokens_spent=min(budget, 500),
    )


async def run_swarm_llm(
    signal: dict,
    *,
    max_agents: int = 5,
    per_agent_budget: int = DEFAULT_PER_AGENT_TOKEN_BUDGET,
) -> list[HypothesisResult]:
    """LLM-backed swarm: generate hypotheses dynamically, then score concurrently.

    Falls back to the deterministic ``run_swarm()`` if LLM mode is disabled
    or the LLM call fails.
    """
    if not _is_llm_enabled():
        return await run_swarm(signal, max_agents=max_agents, per_agent_budget=per_agent_budget)

    hypotheses = await _generate_hypotheses_llm(signal, max_hypotheses=max_agents)
    results = await asyncio.gather(*[
        _score_hypothesis_llm(h, signal, per_agent_budget) for h in hypotheses
    ])
    return list(results)

