---
title: LLM gateway (LiteLLM)
description: Route every live LLM call through a single LiteLLM gateway — assign local or hosted models per task by alias, and get centralized latency/token/cost/error metrics — without changing Intelligence SOC code.
---

# LLM gateway (LiteLLM)

Intelligence SOC runs several distinct LLM workloads — triage, recon, investigation, the
contextual copilot, summaries, reports, and natural-language generation. The
**LiteLLM gateway** is the single entry point for every *live* LLM call these
workloads make. Intelligence SOC asks for a **logical task alias**; the gateway decides
which real provider and model that alias resolves to.

```
Intelligence SOC task ──▶ alias (e.g. "aisoc-triage") ──▶ LiteLLM ──▶ real model
```

This gives operators two things without any Intelligence SOC code change:

1. **Per-task model assignment.** Point `aisoc-triage` at a cheap local model
   and `aisoc-investigation` at a strong hosted one — or swap either at any time
   — by editing one config file.
2. **Centralized observability.** LiteLLM exports per-task latency, tokens,
   cost, errors, retries, and fallbacks on `/metrics`, scraped by the bundled
   Prometheus (job `aisoc-litellm`). This complements the
   [Investigation Ledger](../concepts/llmops.md), which records *what the agent
   decided*; the gateway records *what each model call cost and how it behaved*.

The gateway sits in front of the LLM tier of the
[multi-model router](../concepts/model-router.md). When no live model is
reachable, Intelligence SOC still degrades to its **deterministic offline path** — the
gateway is never on the critical path for a baseline triage.

## Task aliases

The shipped aliases mirror Intelligence SOC's workloads. They live in
`infra/litellm/config.yaml`:

| Alias                 | Workload                                   |
| --------------------- | ------------------------------------------ |
| `aisoc-triage`        | Auto-triage of fused alerts (high volume)  |
| `aisoc-recon`         | Recon / enrichment reasoning               |
| `aisoc-investigation` | Deep multi-step investigation              |
| `aisoc-copilot`       | Contextual analyst copilot                 |
| `aisoc-summary`       | Alert / incident summaries                 |
| `aisoc-report`        | Analyst-facing report write-ups            |
| `aisoc-nl`            | NL→query / NL→detection translation        |
| `aisoc-embed`         | ATT&CK semantic search / RAG embeddings    |

`aisoc-embed` is the one alias that isn't a chat/completion workload — it
requires an **embedding-capable** model (e.g. `text-embedding-3-small`,
`nomic-embed-text-v1.5`), not the chat model `LLM_MODEL` serves, and its
`litellm_params.model` reads from `EMBEDDING_MODEL` instead. The embedding
vector dimension is configured separately via `AISOC_EMBEDDING_DIMENSIONS`
(`services/agents`, default `768`) and must match whatever the configured
model actually outputs — changing `EMBEDDING_MODEL` to a model with a
different native size requires updating that env var too, and dropping/
recreating the `attck_techniques` Qdrant collection if it was already created
at the old dimension.

Each alias's `litellm_params.model` is itself an env var
(`os.environ/LLM_MODEL` by default) rather than a hardcoded literal, so you can
swap the model every alias serves by changing **one** env var and restarting
the `litellm` container — no `config.yaml` edit. To split workloads across
different models again (cheap model for triage, stronger one for
investigation), replace the shared `LLM_MODEL` reference with per-alias
literals or per-alias env vars in `config.yaml` — just keep the alias
*names* unchanged (a CI test asserts they match `model_pins.py` roles).

`router_settings.fallbacks` in `config.yaml` also defines cross-alias
degradation (e.g. `aisoc-investigation` falls back to `aisoc-triage`) so a
single model outage degrades quality before dropping to the deterministic
floor.

## Enable the gateway

The `litellm` service is defined in `docker-compose.yml` and starts with the
stack. **Two separate keys are required** — they serve different purposes and
must not share a variable name:

```bash
LITELLM_MASTER_KEY=<a-strong-key>          # Intelligence SOC's services authenticate to the gateway with this
OPENAI_API_KEY=${LITELLM_MASTER_KEY}       # (set in the app services' environment; docker-compose.yml already
                                            #  defaults it to LITELLM_MASTER_KEY via ${OPENAI_API_KEY:-${LITELLM_MASTER_KEY:-...}})
OPENAI_BASE_URL=http://litellm:4000/v1     # send Intelligence SOC's calls to the gateway (agents + api services)

# Upstream provider credential — a DIFFERENT key, used only by the litellm
# container itself to reach the real backend. For a local/remote LM Studio or
# vLLM box (the shipped default), LM Studio ignores the value, so any
# non-empty string works:
LM_STUDIO_URL=http://<your-lm-studio-host>:1234/v1
LM_STUDIO_API_KEY=lm-studio
LLM_MODEL=openai/gpt-oss-20b               # the model every alias currently serves — change this to swap models
```

`docker-compose.yml` already wires `OPENAI_BASE_URL`/`OPENAI_API_KEY`/
`OPENAI_MODEL` with sensible defaults for the `litellm`, `agents`, and `api`
services, so gateway routing is **on by default** in this stack — you only
need to override `LM_STUDIO_URL` / `LLM_MODEL` (or point `config.yaml` at a
different provider entirely) to change what's actually served.

Intelligence SOC now requests a task **alias** for every live call, so an alias only
resolves when it reaches the gateway. If you don't run the gateway, pin each
role to a concrete provider model instead (the **escape hatch**):

```bash
AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini
AISOC_MODEL_PIN_INVESTIGATION=gpt-4o
# … one per role: triage, recon, investigation, copilot, summary, report, nl
```

With neither the gateway nor pin overrides configured, Intelligence SOC uses its
deterministic offline path. (`OPENAI_MODEL` still applies to the separate
"explain this alert" / BYOK path — it must be a valid gateway alias, e.g.
`aisoc-copilot`, whenever `OPENAI_BASE_URL` points at the gateway.)

For the full request-flow algorithm (alias resolution, BYOK layering,
air-gap enforcement, reasoning-model token budgets), see
[the LLM routing architecture doc](../../../../docs/architecture/llm-routing-and-gateway.md).


## Re-point a task to a local model

Duplicate the alias in `infra/litellm/config.yaml` with a local backend. The
alias name **must stay the same** so Intelligence SOC is unaware of the swap:

```yaml
- model_name: aisoc-triage
  litellm_params:
    model: ollama/llama3.1
    api_base: http://ollama:11434
```

Commented Ollama, vLLM, and Anthropic examples ship in the config. For a fully
offline deployment, see [air-gapped operation](./air-gapped.md), which fronts a
local Ollama.

## Observe

- **Metrics:** `curl http://localhost:4000/metrics` (or the Grafana/Prometheus
  stack under the `monitoring` profile) shows `litellm_*` counters broken down
  by task alias and model.
- **Health:** `curl http://localhost:4000/health/liveliness`.

## Notes

- Host port `4000` is bound to `127.0.0.1` only, like the rest of the stack.
- No provider key is ever written to `infra/litellm/config.yaml` — aliases
  resolve credentials from the process environment (`os.environ/...`).
