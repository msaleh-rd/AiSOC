# Multi-model router

Intelligence SOC's reasoning uses three tiers, cheapest first:

1. **Deterministic** — rules and heuristics (keyword tactic extraction, the
   triage scorer, the confidence model). No network, no cost, reproducible.
2. **ML** — the fusion service's Isolation Forest + LambdaRank scorers.
3. **LLM** — a hosted or local model, used only as a last resort.

The **model router** (`services/agents/app/routing/model_router.py`) is the one
place that decides which tier answers a given request, escalating only when the
cheaper tier isn't confident enough, and **attributing every decision** to the
tier that produced it.

## Why a single router

Before it, the deterministic→LLM fallback was reimplemented independently in NL
query, playbook drafting, "explain this alert", the copilot, and each
sub-agent. Each checked "is a key configured?" and degraded on its own, so there
was no single audit point for *which model answered* or *why the LLM was (or
wasn't) used*. The router unifies that.

## The escalation ladder

```
deterministic ── confident? ──▶ done (tier=deterministic)
      │ no
      ▼
     ML ──────── confident? ──▶ done (tier=ml)
      │ no
      ▼
     LLM ─────────────────────▶ done (tier=llm)
```

Each `RoutingDecision` carries:

- `tier` — which tier produced the answer,
- `model_used` — the concrete model/scorer name,
- `attribution` — a human-readable trail of *why* this tier was chosen and why
  cheaper tiers were insufficient,
- `tiers_considered` — every tier that ran,
- `escalation_blocked_reason` — set whenever the router *wanted* to escalate but
  couldn't (no key, air-gap, deterministic mode, governor circuit open, or the
  LLM tier errored).

## The determinism contract

The router **never silently uses the LLM.** Two independent controls force the
deterministic tier and forbid ML/LLM entirely:

- **`AISOC_DETERMINISTIC=1`** — the canonical determinism switch (air-gapped
  deployments, reproducible evals, cost lockdown).
- **The cost governor** — when a tenant's hard budget is exhausted the governor
  returns a circuit-open decision; the router honours it and drops to
  deterministic-only.

In deterministic mode the router is **reproducible**: the same input yields an
identical decision, because only the pure deterministic tier runs. This is
gated in CI (`services/agents/tests/test_model_router.py`,
`test_determinism_contract_identical_input_identical_decision`).

## What the gate proves

`test_model_router.py` proves the router picks the cheapest sufficient tier,
attributes every decision, never silently reaches the LLM (a skipped or blocked
LLM tier is always recorded), degrades gracefully when the LLM errors, and is
reproducible in deterministic mode.
