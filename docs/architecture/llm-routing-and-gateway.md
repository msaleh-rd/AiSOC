# LLM Routing Architecture & Algorithms

This document explains, in detail, how every live LLM call in Intelligence SOC is
routed, resolved, and degraded — the architecture, the algorithms, and the
current live deployment (a single remote LM Studio box). It complements:

- [`apps/docs/docs/operations/llm-gateway.md`](../../apps/docs/docs/operations/llm-gateway.md) — operator-facing "how to configure it" guide.
- [`apps/docs/docs/concepts/model-router.md`](../../apps/docs/docs/concepts/model-router.md) — the deterministic → ML → LLM escalation ladder used by the agents.
- [`apps/docs/docs/concepts/llmops.md`](../../apps/docs/docs/concepts/llmops.md) — the Investigation Ledger (decision auditing, separate concern from this doc).

---

## 1. Why two independent call paths exist

Intelligence SOC makes live LLM calls from **two structurally different code
paths** that evolved for different reasons and must be understood separately:

| | **Alias-based (agent) path** | **Env-baseline (explain/BYOK) path** |
|---|---|---|
| Entry point | `services/agents/app/llm/factory.py::make_chat_model(role)` | `services/api/app/services/llm_resolver.py` + its agents-side twin `services/agents/app/security/llm_resolver.py` |
| What's sent as `model` | A **logical alias** (`aisoc-triage`, `aisoc-copilot`, …) — never a real model name | A **literal model string** read straight from env/tenant config |
| Who resolves the alias | The LiteLLM gateway (`infra/litellm/config.yaml`) | Whatever `base_url` points at — the caller must already know the real model name (or a valid gateway alias) |
| Used by | DetectAgent, TriageAgent, HuntAgent, RespondAgent, the copilot chat, NL→query translation | `POST /api/v1/alerts/{id}/explain` (Deep Explain), BYOK per-tenant credentials, `nl_detection.py` |
| Override mechanism | `AISOC_MODEL_PIN_<ROLE>` (escape hatch to bypass the gateway) | Per-tenant `TenantLlmCredential` row (BYOK), layered over the env baseline |
| Degrades to | Deterministic tier (model router) | Deterministic template synthesizer (corpus-only explanation) |

**Why not unify them?** The alias path is deliberately gateway-owned so
operators can repoint models with zero code change and zero redeploy. The
explain/BYOK path needs per-**tenant** override (a customer's own OpenAI key
pointed at their own account) — that's a per-request, per-tenant decision that
doesn't fit the alias model, so it resolves `(base_url, model, api_key)`
directly. Both paths are required to agree on one invariant: **if
`OPENAI_BASE_URL` points at the gateway, the model string sent to it must be a
valid gateway alias** (e.g. `aisoc-copilot`), because the gateway has no
concept of `gpt-4o-mini` unless an alias maps to it.

---

## 2. Path 1 — Alias-based routing (agents)

### 2.1 Components

```
Agent code (TriageAgent, HuntAgent, ...)
        │  make_chat_model("triage")
        ▼
services/agents/app/llm/factory.py
        │  resolve_model_alias("triage")  ──▶  services/agents/app/llm/model_pins.py
        │  resolve_base_url()             ──▶  os.environ["OPENAI_BASE_URL"] | ["LLM_BASE_URL"]
        ▼
ChatOpenAI(model="aisoc-triage", base_url="http://litellm:4000/v1")
        │
        ▼
infra/litellm/config.yaml  (LiteLLM gateway, container `litellm`)
        │  model_list[model_name == "aisoc-triage"].litellm_params
        ▼
Real backend (currently: remote LM Studio at LM_STUDIO_URL, model LLM_MODEL)
```

### 2.2 Algorithm: `resolve_model_alias(role)`

```
1. base_pin := _DEFAULT_PINS[role]           # e.g. ModelPin("triage", "aisoc-triage", ["deterministic"])
2. if role not in _DEFAULT_PINS:
       return ModelPin(role, "deterministic", [])   # unknown role ⇒ deterministic-only, never a silent guess
3. override := os.environ.get(f"AISOC_MODEL_PIN_{role.upper()}")
4. if override:
       return ModelPin(role, override, base_pin.fallback_chain)   # bypass the gateway entirely for this role
5. return base_pin
```

Every `ModelPin.resolved_chain()` is *guaranteed* to end in the literal string
`"deterministic"` (`ModelPin.resolved_chain()` appends it if missing). A CI
gate, `verify_pins()`, fails the build if any pin's chain doesn't terminate in
the deterministic floor — there is no configuration that can leave the system
with no fallback.

### 2.3 Algorithm: `resolve_base_url()`

```
1. return os.environ.get("OPENAI_BASE_URL", "").strip()
       or os.environ.get("LLM_BASE_URL", "").strip()
       or None
```

Critically, this **deliberately ignores** the compose-provided
`LLM_GATEWAY_URL` env var. `LLM_GATEWAY_URL` is informational only (tells you
*where* the gateway lives); routing through it requires the *explicit*
`OPENAI_BASE_URL`, because the bearer token semantics differ (gateway master
key vs. a raw provider key) and an accidental silent switch would leak the
wrong credential to the wrong host. This was the actual root cause of a bug
fixed in this session: `docker-compose.yml` set `LLM_GATEWAY_URL` for years
without ever setting `OPENAI_BASE_URL`, so **gateway routing was always a
no-op** — every agent call alias-string (`aisoc-triage`, etc.) was sent to the
provider default (`api.openai.com`), which 400'd, and the caller silently fell
back to deterministic. `preflight_llm()` (§2.4) exists specifically to catch
this class of misconfiguration at boot.

### 2.4 Startup self-check: `preflight_llm()`

```
1. if resolve_base_url() is set: return []          # a gateway/base URL exists — aliases will resolve somewhere
2. unrouted := { resolve_model_alias(r) for r in ALL_ROLES if alias starts with "aisoc-" }
3. if unrouted: emit a boot-time warning naming every alias that will 400
```

This turns a previously-silent misconfiguration (agents quietly running
deterministic-only with no operator signal) into an explicit warning at
container start.

### 2.5 Per-tenant BYOK override (context-scoped)

```
llm_override(api_key=..., base_url=..., model=...):
    contextvars.ContextVar["aisoc_llm_override"].set({...})
    yield                                    # every make_chat_model() call inside this block
    contextvars.ContextVar["aisoc_llm_override"].reset()
```

`make_chat_model()` checks this contextvar **before** falling back to the
role's alias/base URL — so a request-scoped BYOK credential (resolved once via
`app.security.llm_resolver`) transparently overrides the alias for the
duration of one request, without threading the override through every agent
function signature.

---

## 3. Path 2 — Env-baseline resolution (Deep Explain / BYOK)

Two structurally identical implementations exist — `services/api/app/services/llm_resolver.py`
and `services/agents/app/security/llm_resolver.py` — because the API service
uses SQLAlchemy/asyncpg against its own connection pool while the agents
service resolves independently for latency isolation. **Both must agree
byte-for-byte on the algorithm below** (this is a documented, tested
invariant — the two modules' docstrings explicitly cross-reference each
other).

### 3.1 Algorithm: `resolve_llm_config(db, tenant_id) -> LlmConfig`

```
1. (env_base_url, env_model, env_key) := _env_baseline()
   # env_base_url = OPENAI_BASE_URL or LLM_BASE_URL
   # env_model    = OPENAI_MODEL or LLM_MODEL or AISOC_LLM_MODEL
   # env_key      = OPENAI_API_KEY or LLM_API_KEY

2. base_url, model, api_key := env_base_url, env_model, env_key   # env is the floor

3. cred := SELECT * FROM tenant_llm_credentials
             WHERE tenant_id = :tenant_id AND enabled = true
           # RLS-scoped; a DB failure here is caught and logged, cred := None (never raises)

4. if cred is not None:
       if cred.base_url:      base_url := cred.base_url;  tenant_contributed_base_url := true
       if cred.model:         model    := cred.model;      tenant_contributed_model := true
       if cred.api_key_vault: api_key  := decrypt(cred.api_key_vault)  # CredentialVault (Fernet); tenant_contributed_key := true
                              # a decrypt failure does NOT raise — it falls through to env_key,
                              # so a corrupted tenant credential never breaks a tenant that
                              # also has a working env-level fallback.

5. source := classify(tenant_contributed_*, env_contributed_*)
       # "tenant"      — every effective field came from the tenant's own BYOK row
       # "environment" — every effective field came from process env
       # "mixed"       — some fields tenant, some env (e.g. tenant model + env key)
       # "none"        — nothing configured anywhere

6. final_base  := base_url or "https://api.openai.com"
   final_model := model or "gpt-4o-mini"

7. if not api_key:
       return LlmConfig(allowed=False, reason="no API key configured (neither tenant BYOK nor env)")

8. (blocked, reason) := _airgap_blocks(final_base)
       # AISOC_AIRGAPPED=1 AND hostname == "api.openai.com" (or subdomain) ⇒ blocked
       # exact-hostname match only — substring matching would let
       # "evil.com/api.openai.com" slip through, so urlparse().hostname is used.
   if blocked:
       return LlmConfig(allowed=False, reason=reason)

9. return LlmConfig(allowed=True, base_url=final_base, model=final_model, api_key=api_key, source=source)
```

This function **never raises**. Every failure mode (DB error, vault decrypt
failure, no key, air-gap veto) collapses to `allowed=False` with a populated,
human-readable `reason` — the caller (Deep Explain) always has a legitimate,
useful fallback rather than a 500.

### 3.2 The bug this session found and fixed

Both call sites that consume a resolved `LlmConfig` — `services/api/app/services/alert_explain.py::_call_llm_for_summary`
and its twin `services/agents/app/api/explain.py` — built the outbound URL as:

```python
url = f"{base}/v1/chat/completions"   # WRONG when base_url already ends in /v1
```

But every `base_url` in this system is stored **with** its `/v1` suffix already
(OpenAI convention: `https://api.openai.com/v1`, gateway convention:
`http://litellm:4000/v1`). Every *other* LLM call site in the codebase
(`hunts.py`, `knowledge_base.py`, `phishing.py`, `translation.py`, and the
agents factory's own `chat_completions_url()`) correctly does:

```python
completions_url = f"{base_url}/chat/completions"
```

The explain twins' extra `/v1` produced `http://litellm:4000/v1/v1/chat/completions`
→ a 404 from the gateway → silent fallback to the deterministic template
**every single time a real `OPENAI_BASE_URL` was configured**, for as long as
this code existed. Both twins were corrected to match the established
pattern.

### 3.3 The reasoning-model token-budget bug

`gpt-oss-20b` (and other "reasoning" models exposed via an OpenAI-compatible
API) return **both** a `reasoning_content` field (the model's internal
chain-of-thought) and a `content` field (the final answer) inside the same
`choices[0].message`. The two explain call sites had hardcoded
`max_tokens: 360` / `max_tokens: 320` — low enough that the model spent its
*entire* token budget on `reasoning_content` and never emitted a token of
`content`, which the caller then correctly logged as `error="empty_response"`.
Fixed by raising `max_tokens` to `900` and the client timeout from `20s` to
`45s` in both twins, giving the model room to finish reasoning and still write
a final answer.

---

## 4. The LiteLLM gateway itself

### 4.1 Container & config

- Service `litellm` in `docker-compose.yml`, image `ghcr.io/berriai/litellm:main-stable`.
- Config is bind-mounted **read-only**: `./infra/litellm/config.yaml:/etc/litellm/config.yaml:ro` — editing the file and restarting the container is the entire "re-point a model" operation; no image rebuild.
- Bound to `127.0.0.1:4000` only (never exposed beyond the host), same convention as the rest of the stack.
- Health check: `GET /health/liveliness` inside the container, 15s interval / 30s start period / 10 retries.

### 4.2 Alias table (current live mapping)

All 7 aliases currently resolve identically — a single remote box, model
chosen by one env var:

| Alias | `model` | `api_base` | `api_key` |
|---|---|---|---|
| `aisoc-triage` | `os.environ/LLM_MODEL` | `os.environ/LM_STUDIO_URL` | `os.environ/LM_STUDIO_API_KEY` |
| `aisoc-recon` | ″ | ″ | ″ |
| `aisoc-investigation` | ″ | ″ | ″ |
| `aisoc-copilot` | ″ | ″ | ″ |
| `aisoc-summary` | ″ | ″ | ″ |
| `aisoc-report` | ″ | ″ | ″ |
| `aisoc-nl` | ″ | ″ | ″ |

`LLM_MODEL` currently resolves (via `.env` → `docker-compose.yml`'s `litellm`
service environment block) to `openai/gpt-oss-20b`; `LM_STUDIO_URL` to
`http://10.7.75.103:1234/v1`. Because the `model:` field is itself
`os.environ/LLM_MODEL` rather than a hardcoded literal, **swapping the served
model requires only changing one env var and restarting the `litellm`
container** — no `config.yaml` edit.

To split workloads across different models again (e.g. a cheap model for
`aisoc-triage`, a stronger one for `aisoc-investigation`), replace the shared
`os.environ/LLM_MODEL` with per-alias literals or per-alias env vars — the
alias *names* must never change (a CI test asserts they match `model_pins.py`
role names exactly).

### 4.3 Router-level resilience (`router_settings`)

```yaml
router_settings:
  num_retries: 2                 # retry a transient failure (429/5xx/timeout) on the same alias
  fallbacks:
    - aisoc-investigation: ["aisoc-triage"]   # if investigation's model keeps failing, degrade to the cheaper triage model
    - aisoc-report:        ["aisoc-summary"]
    - aisoc-recon:         ["aisoc-triage"]
```

This means a single provider blip degrades **quality** (falls to an adjacent,
usually-cheaper alias) before it ever reaches Intelligence SOC's own
deterministic floor — a second line of defense underneath the per-role
`ModelPin.resolved_chain()` described in §2.2.

### 4.4 Why two API keys are needed, not one

A subtle but important design point fixed this session: the same env var name
(`OPENAI_API_KEY`) cannot serve two different purposes simultaneously:

1. **Upstream credential** — what the `litellm` container uses to authenticate *to* LM Studio / the real provider.
2. **Gateway credential** — what Intelligence SOC's `agents`/`api` services use to authenticate *to* the gateway (must equal `LITELLM_MASTER_KEY`).

Because both consumers read the same host `.env` file, reusing one variable
name for both purposes is a silent footgun (whichever service starts up last
"wins" the value the other one needed). The fix: a dedicated
`LM_STUDIO_API_KEY` env var for purpose (1) — LM Studio ignores its value
entirely, so any non-empty string works — while `OPENAI_API_KEY` for purposes
(2) defaults, via nested Compose interpolation, to `LITELLM_MASTER_KEY`:

```yaml
OPENAI_API_KEY: ${OPENAI_API_KEY:-${LITELLM_MASTER_KEY:-sk-aisoc-local}}
```

### 4.5 `docker-compose.yml` wiring (the actual fix that made routing live)

Before this session, `agents` and `api` never received `OPENAI_BASE_URL` at
all — only the informational `LLM_GATEWAY_URL` was set. Both services'
environment blocks now set all three:

```yaml
OPENAI_BASE_URL: ${OPENAI_BASE_URL:-http://litellm:4000/v1}
OPENAI_API_KEY: ${OPENAI_API_KEY:-${LITELLM_MASTER_KEY:-sk-aisoc-local}}
OPENAI_MODEL: ${OPENAI_MODEL:-aisoc-copilot}     # only consumed by the env-baseline path (§3); must be a valid alias
```

`OPENAI_MODEL` is only relevant to the env-baseline path — the alias-based
agent path (§2) never reads it; it always sends `aisoc-<role>` (or a pin
override).

---

## 5. Escalation ladder above both paths (agents only)

`services/agents/app/routing/model_router.py` sits **above** the alias path
(§2) and decides, per request, whether an LLM call happens at all:

```
deterministic (rules/heuristics/scorers) ── confident? ──▶ done, tier=deterministic
        │ not confident
        ▼
ML (Isolation Forest + LambdaRank, in services/fusion) ── confident? ──▶ done, tier=ml
        │ not confident
        ▼
LLM (§2's alias-based call) ──────────────────────────────▶ done, tier=llm
```

Two independent controls force deterministic-only regardless of gateway
health: `AISOC_DETERMINISTIC=1` (explicit switch — air-gapped deployments,
reproducible evals) and the **cost governor** (a tenant's exhausted budget
opens a circuit that the router honours). Every `RoutingDecision` records
`tier`, `model_used`, a human-readable `attribution`, every tier considered,
and — critically — `escalation_blocked_reason` whenever the router *wanted*
to escalate but couldn't (no key / air-gap / governor / LLM error). This
guarantees the LLM tier is never reached silently; a skipped or blocked LLM
attempt always leaves an audit trail.

---

## 6. End-to-end verified request (reference trace)

Captured during live verification of the current LM Studio deployment
(`gpt-oss-20b` at `10.7.75.103:1234`):

```
POST http://litellm:4000/v1/chat/completions
  Authorization: Bearer <LITELLM_MASTER_KEY>
  {"model": "aisoc-copilot", "messages": [...], "max_tokens": 200}

  → LiteLLM resolves alias "aisoc-copilot" → model=os.environ/LLM_MODEL,
    api_base=os.environ/LM_STUDIO_URL, api_key=os.environ/LM_STUDIO_API_KEY

  → POST http://10.7.75.103:1234/v1/chat/completions  (LM Studio, OpenAI-compatible)

  ← 200 {"system_fingerprint": "gpt-oss-20b",
         "choices": [{"finish_reason": "stop",
                      "message": {"content": "PONG",
                                  "reasoning_content": "User wants reply: \"PONG\"..."}}]}
```

And through the full application path (`POST /api/v1/alerts/{id}/explain`):

```
alert_explain.py::resolve_llm_config()
  → source="environment", base_url="http://litellm:4000/v1", model="aisoc-copilot"
  → _call_llm_for_summary() → POST {base}/chat/completions (no double /v1, post-fix)
  → gateway → LM Studio → real gpt-oss-20b analyst-brief text
  → response: {"llm_used": true, "llm_source": "environment", "llm_reason": ""}
```

---

## 7. Operational notes

- **Reachability is external to this stack.** `10.7.75.103:1234` being
  unreachable (LM Studio server not started, bound to `127.0.0.1` instead of
  `0.0.0.0`, VPN/firewall) is not a Docker networking bug — verify with
  `Test-NetConnection -ComputerName <host> -Port <port>` from the Docker host
  before assuming the gateway/compose wiring is broken.
- **`config.yaml` changes need only a container restart** (bind-mounted,
  read-only). **`docker-compose.yml` env changes and Python code changes to
  `agents`/`api` need an image rebuild** (`docker compose build api agents`)
  followed by `--force-recreate` — the running containers otherwise keep the
  old baked-in code/env.
- **A side effect of enabling `OPENAI_BASE_URL` for `agents`:** the MITRE
  ATT&CK semantic-search embedding seed routine
  (`services/agents/app/tools/mitre_full.py`, uses `openai.AsyncOpenAI()`
  which auto-reads `OPENAI_BASE_URL`) now also routes through the gateway,
  which has no embeddings-capable alias — it 400s in a loop
  (`model=text-embedding-3-large` not in `model_list`). This is pre-existing
  and non-fatal (each batch is wrapped in try/except; it was already broken
  before, just failing on auth instead of routing). Fixing it requires either
  an embeddings-capable model + a dedicated gateway alias, or disabling that
  seed routine — out of scope for the LM-Studio-as-default change.
