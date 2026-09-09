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

| Alias                 | Workload                                   | Shipped default   |
| --------------------- | ------------------------------------------ | ----------------- |
| `aisoc-triage`        | Auto-triage of fused alerts (high volume)  | `gpt-4o-mini`     |
| `aisoc-recon`         | Recon / enrichment reasoning               | `gpt-4o-mini`     |
| `aisoc-investigation` | Deep multi-step investigation              | `gpt-4o`          |
| `aisoc-copilot`       | Contextual analyst copilot                 | `gpt-4o-mini`     |
| `aisoc-summary`       | Alert / incident summaries                 | `gpt-4o-mini`     |
| `aisoc-report`        | Analyst-facing report write-ups            | `gpt-4o`          |
| `aisoc-nl`            | NL→query / NL→detection translation        | `gpt-4o-mini`     |

The "shipped default" is only the *example* mapping in the config — the whole
point is that you change it. The alias names stay constant.

## Enable the gateway

The `litellm` service is defined in `docker-compose.yml` and starts with the
stack. To route Intelligence SOC through it, set in your `.env`:

```bash
LITELLM_MASTER_KEY=<a-strong-key>          # Intelligence SOC authenticates to the gateway with this
OPENAI_API_KEY=<your-real-provider-key>    # LiteLLM uses this to reach the upstream model
OPENAI_BASE_URL=http://litellm:4000/v1     # send Intelligence SOC's calls to the gateway
# and set Intelligence SOC's client key to the gateway key:
# OPENAI_API_KEY=${LITELLM_MASTER_KEY}     # (in the Intelligence SOC services' environment)
```

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
"explain this alert" / BYOK path.)

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
