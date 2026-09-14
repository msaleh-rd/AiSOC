"""LLM synthesis of the PageRank RCA result into an analyst-readable narrative.

The PageRank scorer produces structured causal candidates (root cause entity,
temporal sequence, blast radius, evidence counts) but no prose. This module
asks the investigation LLM to synthesize those candidates into a short causal
narrative — what likely happened, in what order, and whether the evidence
actually supports the computed root cause.

Best-effort by design: any failure returns ``None`` and the deterministic
PageRank result remains authoritative. The narrative is additive context,
never a replacement for the scored analysis.
"""

from __future__ import annotations

import os

import httpx
import structlog

from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted

logger = structlog.get_logger()

_MAX_NARRATIVE_CHARS = 2000


def _build_prompt(rca: dict, alert_summary: str) -> str:
    sequence_lines = []
    for step in (rca.get("temporal_sequence") or [])[:8]:
        if isinstance(step, dict):
            ts = step.get("timestamp", "?")
            entity = step.get("entity", step.get("entity_id", "?"))
            action = step.get("action", step.get("event", "?"))
            sequence_lines.append(f"- {ts} | {entity} | {action}")
        else:
            sequence_lines.append(f"- {step}")

    pagerank = rca.get("pagerank_scores") or {}
    top_entities = sorted(pagerank.items(), key=lambda kv: kv[1], reverse=True)[:5]
    pagerank_lines = [f"- {entity}: {score:.4f}" for entity, score in top_entities]

    return (
        "You are a senior SOC analyst reviewing an automated root cause "
        "analysis. Using ONLY the structured findings below, write a concise "
        "causal narrative (3-6 sentences, plain text, no markdown): what most "
        "likely happened and in what order, whether the evidence genuinely "
        "supports the computed root cause (say so plainly if it is weak), and "
        "what the investigation should focus on next. Do not invent entities "
        "or events that are not listed.\n\n"
        f"Alert under investigation:\n{wrap_untrusted(sanitize_text(alert_summary), label='alert_summary')}\n\n"
        "Root cause analysis (PageRank over the causal event graph):\n"
        f"- Computed root cause entity: {rca.get('root_cause_entity', 'unknown')}\n"
        f"- Target (alerting) entity: {rca.get('target_entity', 'unknown')}\n"
        f"- Confidence: {rca.get('confidence', 0)} ({rca.get('confidence_level', 'unknown')})\n"
        f"- Inferred attack type: {rca.get('attack_type', 'unknown')}\n"
        f"- Supporting evidence items: {rca.get('supporting_evidence_count', 0)}\n"
        f"- Contradicting evidence items: {rca.get('contradicting_evidence_count', 0)}\n"
        f"- Estimated blast radius (downstream entities): {rca.get('estimated_blast_radius', 0)}\n"
        f"- Remediation complexity: {rca.get('remediation_complexity', 'unknown')}\n\n"
        "Temporal sequence (chronological):\n"
        + ("\n".join(sequence_lines) or "- (none)")
        + "\n\nTop entities by causal influence (PageRank):\n"
        + ("\n".join(pagerank_lines) or "- (none)")
    )


async def synthesize_rca_narrative(rca: dict, alert_summary: str) -> str | None:
    """Ask the investigation LLM for a causal narrative over the RCA result.

    Returns the narrative text, or ``None`` on any failure (LLM unreachable,
    empty response, etc.) — the caller treats the narrative as optional.
    """
    if not rca:
        return None

    litellm_url = os.getenv("LITELLM_URL", "http://litellm:4000")
    api_key = os.getenv("OPENAI_API_KEY", "") or os.getenv("LITELLM_MASTER_KEY", "")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{litellm_url}/v1/chat/completions",
                json={
                    "model": os.getenv("AISOC_RCA_MODEL", "aisoc-investigation"),
                    "messages": [
                        {"role": "user", "content": _build_prompt(rca, alert_summary)}
                    ],
                    "temperature": 0.3,
                    # Reasoning models burn hidden tokens against max_tokens;
                    # keep headroom so the prose answer isn't truncated.
                    "max_tokens": 2000,
                    # No response_format — LM Studio-style backends reject
                    # type=json_object, and we want plain text anyway.
                },
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            content = (data["choices"][0]["message"]["content"] or "").strip()
            if not content:
                return None
            return content[:_MAX_NARRATIVE_CHARS]
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "rca.synthesis_failed",
            error=str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
        return None
