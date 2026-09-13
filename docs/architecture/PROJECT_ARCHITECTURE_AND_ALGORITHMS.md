# Intelligence SOC (AiSOC) — Full Project Architecture & Algorithms

This is the current, code-verified reference for how the whole platform is
built and how every non-trivial algorithm in it works. It supersedes the
narrative sections of [`SYSTEM_DESIGN.md`](./SYSTEM_DESIGN.md) wherever the two
disagree — this document was written by reading the current source, not the
original design intent. `SYSTEM_DESIGN.md` still has good historical framing
(knowledge graph node/edge tables, ITSM fan-out, connector platform, v2.x
timeline) and is not being deleted; this document is the current-state
companion, and [`llm-routing-and-gateway.md`](./llm-routing-and-gateway.md) is
the LLM-specific deep-dive referenced throughout.

---

## 1. End-to-end event flow (what is actually wired today)

```
Connectors (poll)  ──┐
Webhooks / Universal Capture ──┤
osquery-tls (endpoint telemetry) ──┤
                                    ▼
                         services/ingest (Go)
                         ── OCSF normalization
                         ── ATT&CK technique tagging
                         ── CISA KEV correlation
                         ── graph-at-ingest (async, non-blocking)
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                  Kafka: raw_events      Neo4j (entity graph)
                         │
                         ▼
                services/fusion (Python consumer)
                 1. validate event schema → DLQ poison events
                 2. windowed/stateless detection engines (Redis ZSET windows)
                 3. promote OCSF event → RawAlert (severity floor + Findings category)
                 4. Redis fingerprint dedup (sliding window)
                 5. entity/ATT&CK correlation
                 6. ML scoring (Isolation Forest + LightGBM LambdaRank)
                 7. confidence scoring (independent of severity)
                 8. narrative generation (deterministic correlation copy)
                         │
                         ▼
              Postgres (fused alerts, RLS + query-layer tenant filter)
                         │
                         ▼
              services/realtime (WebSocket fan-out) → apps/web console
```

This is the **actual wired spine** as of this writing — confirmed by reading
`services/fusion/app/workers/consumer.py`, `services/fusion/app/services/{promoter,fusion_engine,detection_engine,windowed_detection,dlq}.py`,
and `services/ingest/internal/{handler,graph,enrichment}/`. Detection
execution against the live stream **is** wired (via `detection_engine.py` +
`windowed_detection.py` inside the fusion consumer) — this is more current
than the "populating the lake / detect-worker" caveat in older notes, which
referred to a separate ClickHouse-lake batch detection path, not the
real-time fusion path.

Poison events never crash the consumer or get silently dropped — they are
schema-validated first (`event_schema.py`) and routed to a dead-letter queue
(`dlq.py`) on failure, with the failure reason preserved for operator review.

### 1.1 Local log ingestion path (operator workflow)

For real exported telemetry (for example CAM-style Wazuh + Suricata dumps),
the host-side importer in `scripts/ingest_local_logs.py` sends batches to the
same public ingest contract used by connectors:

```
POST http://localhost:8081/v1/ingest/batch
X-Tenant-ID: 00000000-0000-0000-0000-000000000001 (default)
```

Supported files in this first-pass importer:

- `security/wazuh__alerts_*.json` (JSON-lines)
- `network/*_suricata_eve.json` (`event_type == "alert"` only)

Operationally this must run against the full compose stack (`docker compose up -d`),
not the slim `pnpm aisoc:demo` profile, because the script depends on the
`services/ingest` endpoint (port 8081) and downstream Kafka/fusion consumers.

---

## 2. Ingest (`services/ingest`, Go)

### 2.1 Normalization

`internal/normalizer/normalizer.go` converts each vendor's raw payload into a
canonical OCSF-shaped envelope. Severity is remapped through the platform's
five-tier ladder (`info | low | medium | high | critical`) — vendor-native
ladders that publish a distinct `critical` tier (Azure, GCP SCC, GitHub,
ServiceNow P1, GuardDuty ≥8.0, etc.) map to `critical`, never collapsed into
`high`. Event identity fields (source, event type, timestamps) are normalized
so downstream fingerprinting/dedup is stable across connectors emitting the
same underlying event through different transports.

### 2.2 CISA KEV correlation

`internal/enrichment/vuln.go` extracts CVE identifiers from the normalized
event, looks them up against an in-process CISA Known Exploited
Vulnerabilities index, and — on a match — emits a `VULNERABILITY_MATCH` event
onto a separate Kafka topic. This lets a vulnerability-scanning connector's
finding be cross-referenced against active exploitation in the wild without a
synchronous call per event.

### 2.3 Graph-at-ingest

`internal/graph/writer.go` + `internal/graph/extractor.go` maintain a Neo4j
entity graph (17 node labels / 14 edge types — `User`, `Asset`, `Process`,
`IP`, `Domain`, `Alert`, `Detection`, …) written **inline** with Kafka
consumption, not as a separate batch job:

```
1. Each normalized event is queued into an internal graph-write channel
   (non-blocking send — if the queue is full, the event is dropped for
   graph purposes only; the ingest hot path is never stalled by graph
   back-pressure).
2. A background worker drains the channel and batches writes.
3. Batches are flushed to Neo4j via UNWIND + MERGE Cypher (idempotent
   upsert-by-key), one statement per node label / edge type per batch,
   rather than one round-trip per entity.
4. ATT&CK-tagged events additionally MERGE a (:Detection)-[:USES]->(:Technique)
   edge so the graph carries which technique triggered which node.
```

The "drop-on-backpressure, never stall ingest" design is the key latency
guarantee — graph enrichment is best-effort and eventually consistent, while
OCSF normalization + Kafka publish is the guaranteed hot path.

---

## 3. Fusion (`services/fusion`, Python)

### 3.1 Event validation and DLQ

Every consumed event is validated against a schema (`event_schema.py`) before
any further processing. A failure does not crash the consumer or silently
drop the event — it is written to a dead-letter queue (`dlq.py`) with the
validation failure reason attached, so operators can inspect and replay
malformed producer output instead of losing it.

### 3.2 Promotion

`promoter.py` decides whether a normalized OCSF event becomes a `RawAlert`
worth fusing at all — the algorithm is a category check (events tagged
`Findings`) OR a severity floor (events at or above a configured threshold
bypass the category check). This keeps low-value telemetry (routine
successful logins, benign process starts) out of the alert pipeline entirely,
while still promoting anything severe regardless of its OCSF category.

### 3.3 Deduplication

`deduplicator.py` computes a SHA-256 **fingerprint** per alert (stable across
identical re-ingests — this is what makes re-running the same log-ingestion
script idempotent) and stores it as a Redis key with a sliding-window TTL
(`dedup_window_seconds`). A second occurrence of the same fingerprint within
the window is flagged as a duplicate and linked back to the original alert ID
rather than creating a new alert row.

### 3.4 Windowed / stateless detection

`detection_engine.py` + `windowed_detection.py` run rule-style detections
directly against the raw event stream (not just against already-fused
alerts). Windowed detections use **Redis ZSETs keyed per entity** — each
matching event is scored into the ZSET by timestamp, and a detection fires
when the count of members within a trailing time window crosses a configured
threshold (e.g. "N failed logins for the same user within 5 minutes"). This
is the mechanism behind burst/frequency-based detections that a single-event
rule engine can't express.

### 3.5 ML scoring (`ml_scorer.py`)

Two independent models, both **lazily trained** and both falling back to a
heuristic until enough data exists — the service is never blocked waiting on
a cold-start model:

**Anomaly score** — scikit-learn `IsolationForest`, trained once
`_MIN_SAMPLES_FOR_TRAINING = 50` feature vectors have accumulated in an
in-memory rolling buffer. Feature vector (`_featurize`, 13 dimensions):

```
[severity(0-4), has_src_ip, has_dst_ip, has_hostname, has_username,
 has_file_hash, has_domain, has_url, num_mitre_tactics, num_mitre_techniques,
 num_tags, risk_score, hour_of_day]
```

Cold-start heuristic (`_heuristic_anomaly`): `+0.3` if a file hash is present,
`+0.2` if both src and dst IP are present, `+min(0.3, techniques×0.05)` for
MITRE technique density, `+severity×0.05` — capped at 1.0. The intuition:
alerts carrying more distinct IOC types and more ATT&CK technique coverage
are treated as more anomalous even before the model has any training data.

**Priority score** — LightGBM `LGBMRanker` (LambdaRank objective), trained
once `_MIN_FEEDBACK_FOR_RANKER = 30` analyst feedback rows exist
(`POST /ml/feedback` with `is_true_positive` + `assigned_priority` 1-5).
Cold-start heuristic (`_heuristic_priority`): `severity/4.0` as the base, plus
small additive bonuses for each populated IOC field (src_ip +0.1, hostname
+0.05, username +0.05, file_hash +0.1, mitre_techniques +0.05) — a lightweight
proxy for "how actionable is this alert" before the ranker has training
signal.

Both models are held **in memory**, hot-swapped behind a lock when retrained,
and the old model stays live until the new one is ready — there is never a
window where scoring is unavailable during a retrain.

### 3.6 Confidence scoring (`confidence.py`)

A separate, **stateless, synchronous** `ConfidenceScorer` — deliberately not
async, because confidence is a pure projection of fields already present on
the `FusedAlert`, not an enrichment step that hits the network. It combines
several independently-weighted factors (severity contribution, IOC-field
population count via a step function — 0 contribution for ≤2 populated
fields, 0.5 for 3-4, 1.0 for 5+ — and other signals) into a `confidence_label`
(`low|medium|high`), a `confidence_score` (0-100), and a `confidence_rationale`
list so the UI can render *why* a given confidence was assigned, not just the
number. Confidence is intentionally **independent of severity** — a
`critical`-severity alert with thin evidence can carry `low` confidence, and
vice versa. The whole scorer is feature-flaggable (`AISOC_FEATURE_CONFIDENCE`)
and degrades to safe model defaults (`MEDIUM` / `0.5` / empty rationale) when
disabled, rather than raising.

### 3.7 Narrative generation

`services/fusion/app/services/narrative.py` writes deterministic correlation
copy **at fuse time** (not on-demand) — a plain-English sentence describing
why a set of underlying events were correlated into one alert. This backs the
Investigation Rail's narrative field (`GET /api/v1/alerts/{id}`) and is kept
in sync with a vendored copy in `services/api/app/_vendor/narrative.py` via
`scripts/sync_vendored_narrative.py`.

---

## 4. Detection rule engine (`services/api/app/services/rule_engine.py`)

### 4.1 Supported rule languages

| Type | Execution |
|---|---|
| Sigma | Custom evaluator with a **whitelisted recursive-descent condition parser** — not `eval()`/`compile()` on user input. The parser only accepts a fixed grammar (AND/OR/NOT, field comparisons, `1 of`/`all of` selectors) and rejects anything outside it. |
| YARA | `yara-python`, targets file/memory artifacts. |
| KQL | Translated to ClickHouse SQL for event analytics. |
| EQL / Lucene / Regex | Direct OpenSearch query execution. |

### 4.2 Why the whitelisted parser matters

This replaced an earlier `eval()`-based condition evaluator (a security-wave
fix — see §7). A recursive-descent parser walks the rule's `condition` string
token-by-token, builds an AST out of a closed set of node types, and
evaluates that AST against the event — a malicious or malformed condition
string can express at most the closed grammar, never arbitrary Python.

### 4.3 Detection corpus size vs. executable count

`detections/` holds roughly 6,975 rule files on disk, but only ~939 are
**executable** today (861 native + 77 Sigma-imported + 1 community) — the
remainder are quarantined/disabled pending validation. This split is tracked
in a truth-table (`docs/detections/truth-table.md`) and is a hard transparency
rule: quarantined/aspirational rules must never be presented as executable in
docs, marketing, or benchmark claims.

---

## 5. AI agents (`services/agents`) — the four-agent architecture

The agent layer was rebranded from an earlier `PlannerAgent → {Endpoint,
Identity, Network, Cloud, Email, ThreatIntel, Vulnerability}Agent →
SynthesisAgent → ActionAgent` fan-out DAG to a **four-agent funnel**, each
owning one stage of the detect→respond pipeline:

```
DetectAgent → TriageAgent → HuntAgent → RespondAgent
```

Back-compat aliases preserve the old agent class names as imports so existing
integrations don't break; the funnel-stage framing is documented per-agent in
`apps/docs/docs/console/funnel-kpis.md`.

### 5.1 Graph orchestration (`services/agents/app/graph/workflow.py`)

```
1. Auto-triage gate: run a cheap first-pass classification.
2. If high-confidence benign/false-positive → route straight to END
   (no further agent spend on an alert already resolved with confidence).
3. Otherwise → run the full pipeline: triage → enrichment → investigation
   → attack-path reconstruction.
4. Errors during triage escalate rather than silently truncating the run.
```

### 5.2 Supervised mode (`app/orchestrator/supervisor.py`)

A feature-flagged ReAct-style observe→reason→act loop that, when enabled,
invokes the deeper evidence-gathering / compression / swarm / RCA machinery
below on top of the base four-stage funnel — the base funnel always runs;
supervision adds depth for cases that warrant it. `decide()` implements:

```
1. if iteration_count >= max_iterations:
       return finalize_response          # hard budget stop, bypasses the
                                          # "finalize needs findings" guard
2. target_entities := _sanitize_entities(proposed_targets, state)
       # drops any entity the LLM proposed acting on that isn't actually
       # present in state.entities / raw_alert (hostname, username, src_ip,
       # dst_ip, entity_id, entity) — a hallucinated pivot target is
       # silently dropped, never acted on
3. _detect_goal_drift(current_goal, state.supervisor_history[0])
       # heuristic vocabulary-overlap check against the ORIGINAL alert
       # context; logs a warning on drift, never blocks — advisory only
4. return the validated next action (gather_evidence | run_swarm |
       perform_rca | compress_events | finalize_response)
```

`app/graph/runner.py::run_full_investigation()` is the single call site that
selects the graph to run: it reads `AISOC_AGENT_SUPERVISED_MODE` (default
off) and picks `get_supervised_graph()` over the fixed `investigation_graph`
when enabled, threading `InvestigationBudget.max_tool_calls` into
`state.max_iterations` so the supervisor's own budget-stop check (step 1
above) is driven by the same budget the runner enforces via its wall-clock
`asyncio.timeout`. Enabling the flag changes no behavior for existing
deployments until explicitly opted into — see §5.8 for why this graph was,
for a time, unreachable from the production UI despite being fully wired.

### 5.3 Model routing (escalation ladder)

`app/routing/model_router.py`'s `ModelRouter.route()` implements the
deterministic → ML → LLM ladder described in
[the model-router doc](../../apps/docs/docs/concepts/model-router.md), with
the actual algorithm:

```
attribution := []
deterministic_only := forced_by_construction
                     OR AISOC_DETERMINISTIC env flag is set
                     OR cost_governor.check(tenant, fingerprint).use_llm == False

det := deterministic_fn(request)     # tier 1 ALWAYS runs — it's the floor
if det.confidence >= confidence_floor OR no higher tier configured/allowed:
    return Decision(tier=DETERMINISTIC, ...)

if ml_fn configured:
    ml := ml_fn(request)             # tier 2
    if ml.confidence >= confidence_floor OR no llm_fn configured:
        return Decision(tier=ML, ...)

llm := llm_fn(request)               # tier 3 — last resort
return Decision(tier=LLM, ..., attribution=[...])
```

Every `RoutingDecision` records `tier`, `model_used`, a human-readable
`attribution` trail, every `tiers_considered`, and — whenever the router
*wanted* to escalate but couldn't — an explicit `escalation_blocked_reason`
(no ML/LLM tier configured, deterministic-only mode, or governor veto). A
governor exception never crashes routing — it's caught, logged, and treated
as "governor allows" so a governor bug can't accidentally block all LLM
spend platform-wide.

### 5.4 Compression pipeline (`app/compression/pipeline.py`)

An explicit 7-stage reduction pipeline that compresses raw investigation
evidence (event logs, tool outputs, prior agent reasoning) down to a token
budget the next stage can actually consume, with named stage markers so the
Investigation Ledger can show exactly what was dropped/summarized at each
stage rather than presenting compression as a black box.

### 5.5 Root-cause analysis (`app/rca/`)

RCA is **PageRank-based causal inference**, not an LLM prompt:
`causal_graph.py` builds a directed graph of candidate causal relationships
between observed events (who/what preceded what), and `pagerank_scorer.py`
runs real `networkx.pagerank()` (the library's scipy-backed implementation,
not a hand-rolled power-iteration loop) over that graph to rank which
upstream event is most likely the root cause — the same algorithm class
used for web-page authority ranking, applied here to "which event caused the
most downstream effects." This is deterministic and reproducible given the
same causal graph, unlike an LLM-generated root-cause narrative.

Two correctness properties worth calling out explicitly, since both were
bugs until they were fixed and pinned with regression tests
(`tests/test_rca_pagerank.py`):

- **Target-entity selection.** The entity RCA treats as "the symptom to
  explain" is derived from the actual alert (`normalise_event(raw_alert).entity_id`),
  not from "whichever event happens to be first in the events list" — the
  latter silently picked an arbitrary bystander entity whenever event
  ordering didn't match causal ordering.
- **Dependency edge direction and criticality.** Edges run **cause → effect**
  (`dependency_entity → dependent_entity`), matching how an attacker's
  actions actually flow. Criticality ("how many things does this entity's
  compromise put at risk") is computed from an entity's **successors**
  (downstream dependents) — using predecessors here would have scored a
  leaf/sink node as more critical than the hub causing it, backwards from
  the intended "blast radius" semantics.

### 5.6 Competing-hypothesis swarm (`app/swarm/`)

For sufficiently complex alerts (gated by `complexity.py`'s
`assess_complexity()` — technique count **and** distinct MITRE **tactic**
count, since an alert touching one technique across many tactics is a
different shape of complexity than many techniques in one tactic), the
supervisor can dispatch `run_swarm_node`, which:

```
1. generate_hypotheses_llm(context)  → N competing root-cause hypotheses,
       one real LiteLLM call; real token usage read from the response's
       `usage` field (prompt + completion tokens), not a hardcoded estimate
2. evaluate each hypothesis deterministically against the evidence
       (tokens_spent=0 — no LLM call in this step)
3. debate/adjudicate → winning hypothesis, with the step-1 token cost
       attributed proportionally across the hypotheses it produced
```

The deterministic evaluation step never calls an LLM at all — only
hypothesis *generation* costs tokens — so a swarm run's real cost is exactly
one LLM round-trip, not one-per-hypothesis.

### 5.7 Memory / distillation (`app/memory/`)

`outcomes.py` records what actually happened after an agent's recommendation
(was the case confirmed, dismissed, escalated); `distillation.py` compresses
accumulated outcome history into signature-keyed priors (`classification:tactic:technique`)
so past investigation patterns inform future triage confidence without
replaying full transcripts. Priors are **tenant-scoped**
(`_tenant_priors: dict[tenant_id, dict[signature, SignaturePrior]]`) — an
earlier flat, single-dict design overwrote all tenants' priors on every
`distill()` call, which would have let one tenant's outcome history bias
another tenant's triage confidence. `ensure_fresh(tenant_id, max_age_seconds)`
auto-refreshes a tenant's priors on demand rather than requiring an external
scheduler.

The adjustment is wired into the **live** triage path, not just available
for offline analysis: both `triage_agent.py` and `auto_triage_agent.py` call
`get_memory_verdict_adjustment(signature, tenant_id)` after computing a
baseline confidence, clamp the adjustment to ±0.10, and record the basis in
`confidence_basis` for auditability — in `auto_triage_agent.py` this happens
*before* the auto-close threshold check, so a repeated false-positive
signature can actually suppress a future auto-close decision, not just
annotate it after the fact.

### 5.8 Orchestrator entry points and reachability

Three independent orchestrators exist under `services/agents`, all
registered behind one dispatcher, `app/api/investigate.py::_investigate_stream()`,
which is what the Case Workspace UI's `POST /cases/{case_id}/investigate`
actually calls (via `services/api`'s proxy):

| Orchestrator | Selected by | Notes |
|---|---|---|
| `InvestigatorOrchestrator` (`app/investigator/`) | default | legacy recon/forensic/responder shape |
| `RouterOrchestrator` (`app/orchestrator/router.py`) | `AISOC_INVESTIGATE_USE_ROUTER=1` | four-agent parallel/sequential fan-out (T2.2) |
| `run_full_investigation()` via `GraphOrchestratorAdapter` (`app/graph/adapter.py`) | `AISOC_INVESTIGATE_USE_GRAPH=1` | the fixed/supervised LangGraph pipeline (§5.1–§5.2, §5.5–§5.7) |

All default off except the legacy path, and flags are checked in priority
order (graph > router > investigator) so an operator can opt in
incrementally. This third entry exists because the LangGraph pipeline was,
for a time, **only** reachable via a separate, simpler API
(`app/api/router.py`'s `POST /investigations`) that the production UI never
called — meaning the RCA/swarm/supervised-mode work above was fully wired
and tested in isolation but invisible in the real product. `GraphOrchestratorAdapter`
adapts `run_full_investigation()` (which only returns a final state, no
per-node stream) to the same `stream_kwargs()` contract the other two
orchestrators expose — one terminal `done` (or `error`) event carrying a
rendered Markdown/HTML report (now with a Root Cause Analysis section, see
`app/orchestrator/report.py`) plus the full state, including
`rca_findings` / `supervisor_history` / `compressed_events` for cases that
want to inspect the deeper machinery.

### 5.9 Temporal.io durability overlay (optional, `app/temporal/`)

A fourth, highest-priority orchestrator option (`AISOC_AGENT_TEMPORAL_MODE=1`,
default off) that trades in-process execution for durable, replay-safe
execution — useful for long-running investigations that must survive a
worker restart or a multi-hour human-in-the-loop approval wait. It does not
duplicate investigation logic: `InvestigationWorkflow` re-runs the same
5-phase sequence (auto-triage → triage → evidence-gathering →
compression → swarm → RCA) as **Temporal activities**, each of which is a
thin wrapper delegating to the exact same node functions
`app/graph/workflow.py` uses for the in-process graph.

```
1. run auto_triage; if it auto-closes the alert, return immediately
2. loop (bounded by max_reinvestigations):
       run triage → gather_evidence → compress_events → run_swarm → perform_rca
       if confidence >= confidence_threshold: break
3. if any proposed_action requires approval:
       pause and wait_condition() on the `approve` signal (1h timeout,
       defaults to rejecting the actions if no reviewer responds in time)
4. run finalize_response; return the final state
```

Progress is queryable at any point (`get_progress` — phase, verdict,
confidence, findings count) so `TemporalOrchestratorAdapter` can synthesize
`step` events for the same streaming contract the other orchestrators use.
The workflow only ever manipulates plain `dict` state (never constructs
`InvestigationState` directly) to satisfy Temporal's deterministic-replay
requirement, since that model's `run_id`/`started_at` fields use
non-deterministic `default_factory` callables. Requires a running Temporal
server + worker (`python -m app.temporal.worker`), both gated behind a
`temporal` Docker Compose profile that's off by default; `temporalio` is an
optional Poetry extra (`poetry install -E temporal`) with zero import-time
cost on the default request path.

---

## 6. UEBA (`services/ueba`)

### 6.1 Per-entity baseline — Welford's online algorithm

`services/ueba/app/services/baseline.py` maintains a running mean/variance
**per feature, per entity** without ever re-reading the full historical
window — classic Welford's algorithm:

```
n     ← n + 1
δ     ← x − mean
mean  ← mean + δ/n
δ2    ← x − mean            (using the UPDATED mean)
M2    ← M2 + δ·δ2
variance = M2 / (n−1)   for n > 1;  0 otherwise
std   = √variance
```

### 6.2 Z-score with an honest "unknown" state

`compute_z_score()` returns `None` — not `0.0` — whenever a feature can't be
meaningfully scored: never observed, fewer than `min_baseline_samples`
observations, or a degenerate (near-zero) standard deviation. This last case
is common in practice (service accounts and batch jobs converge on a
perfectly constant behavior pattern, collapsing `std → 0`), and returning
`0.0` for it would make an *unscoreable* entity indistinguishable from one
sitting exactly on its own mean — silently hiding risk instead of flagging
"we don't know." Callers must treat `None` as "unknown," never coerce it to a
number.

### 6.3 Composite scoring — root-sum-of-squares

`services/ueba/app/services/scoring.py`'s `_composite_score()` combines
multiple per-feature z-scores into one anomaly score via **root-sum-of-squares**
(the Euclidean norm of the z-score vector), explicitly **excluding** any
feature whose z-score is `None` rather than treating it as `0`:

```
composite = min(√(Σ zᵢ²), 10.0)     for zᵢ ≠ None
```

The result is classified into a risk level: `≥6.0 → critical`, `≥4.0 → high`,
`≥ anomaly_threshold → medium`, else `low`. An entity with zero scoreable
features produces **no anomaly record at all** (rather than a false "score 0,
all clear") — the composite score's job is to report deviation, not to
assert normalcy it has no evidence for.

### 6.4 Peer-group deviation (`peer_group.py`)

A second, independent deviation signal computed against a peer cohort (same
role/department/team) rather than the entity's own history — this catches an
entity that has *always* behaved unusually (and would therefore look normal
against its own baseline) but is unusual relative to peers doing the same
job. Blended with the personal-baseline composite score for the final
anomaly verdict.

---

## 7. SOAR / response actions (`services/actions`)

### 7.1 Blast-radius gate (`blast_radius.py`)

```
blast_radius := ACTION_BLAST_RADIUS[action_type]     # static per-action-type table
if action_type in APPROVAL_REQUIRED_ACTIONS:
    return AWAITING_APPROVAL                          # policy override, ignores blast radius entirely
if order(blast_radius) > order(AUTO_EXECUTE_LIMIT = MEDIUM):
    return AWAITING_APPROVAL
return APPROVED
```

Blast radius has five ordered tiers: `MINIMAL < LOW < MEDIUM < HIGH <
CRITICAL`. `MEDIUM` is the ceiling for any form of automatic execution — HIGH
and CRITICAL always require a human, regardless of confidence.

### 7.2 Unified autonomy policy (`unified_autonomy.py`)

Combines model **confidence** with blast radius and **reversibility** into a
single decision — previously these lived in separate, disconnected gates so
confidence never actually influenced whether an action executed:

```
if blast_radius == CRITICAL:              → QUEUED_APPROVAL (always, no exception)
if not reversible(action_type):           → QUEUED_APPROVAL (can't undo a wrong call)
if blast_radius == HIGH:                  → QUEUED_APPROVAL (even if reversible)
if blast_radius == LOW  and confidence >= 0.85: → AUTO
if blast_radius == MEDIUM and confidence >= 0.95: → AUTO   (higher bar — wider blast)
otherwise:                                → QUEUED_APPROVAL
```

This is the platform's **"aggressive-but-safe"** posture: a reversible,
low-blast action with high model confidence can auto-execute (bounded impact,
undoable), while anything irreversible or wide-blast always stops for a
human, no matter how confident the model is.

### 7.3 L0–L4 automation maturity (`services/actions/app/services/maturity.py`)

Runtime implementation of the maturity ladder documented in
[`automation-maturity.md`](../../apps/docs/docs/concepts/automation-maturity.md):
`L0` (fully manual) through `L4` (fully autonomous closure with human
sign-off retained as an audit control, not a blocking gate). The evaluator
combines the tenant's configured maturity level with the unified-autonomy
decision above — a tenant capped at `L1` never auto-executes regardless of
what the confidence/blast-radius math would otherwise permit; `L4` allows a
whitelisted set of action types to auto-execute even at MEDIUM blast radius
if every other gate passes.

### 7.4 Honest rollback (`rollback.py`)

Every action that claims to be reversible ships a **real** reverser
function, not a no-op — the rollback module is explicit about which actions
have a genuine undo path and refuses to mark an action reversible in the
blast-radius/autonomy math (§7.2) unless a working reverser is registered for
it. Response actions return `simulated` results by default unless real vendor
credentials are plumbed in — this is a deliberate honesty gate: the platform
never claims to have executed a real action it only simulated.

### 7.5 SSRF guard (`services/agents/app/playbook/ssrf_guard.py`)

Every outbound `http_request`/`notify` playbook step is routed through a
guard that enforces: a scheme allow-list (no `file://`, `gopher://`, etc.),
hostname **resolution** followed by an IP allow-list check (not just a
string match on the hostname — this blocks DNS-rebinding tricks), and a
cloud-metadata IP block list (`169.254.169.254` and equivalents) that applies
**even when private IPs are otherwise explicitly allowed** by policy — so a
playbook author can't accidentally (or maliciously) craft a step that
exfiltrates instance credentials via the metadata endpoint.

---

## 8. Multi-tenancy & security hardening

### 8.1 Tenant isolation, per data store

Isolation is enforced **at the query layer** for every stateful store, with
Postgres Row-Level Security as defense-in-depth rather than the sole
mechanism (a lesson from a prior security-wave finding: RLS alone was not
sufficient on `/hunts` and `/cases`):

| Store | Isolation mechanism |
|---|---|
| Postgres | `set_config('app.current_tenant_id', ...)` per session (`db/rls.py`) **plus** explicit `WHERE tenant_id = :tid` predicates in query code (`hunts.py`, `cases`) |
| ClickHouse | `lake_sql.py` parses user SQL into an AST and injects a `tenant_id` predicate before execution — a user cannot craft a query that reads across tenants even via a subquery |
| Neo4j | Every node carries a `tenant_id` property; all graph service queries filter on it |
| Redis | Key-prefixed (`tenant:{tid}:...`) |
| Kafka | `X-Tenant-ID` header / `tenant_id` envelope field, filtered by downstream consumers |
| Qdrant | `tenant_id` in point payloads + a mandatory query filter (public threat-intel feed data is intentionally global/unscoped; only tenant-private embeddings are isolated) |

A registry-based test gate (`tests/isolation/stores.py` +
`tests/isolation/test_registry.py`) requires every stateful store to
**declare** its isolation coverage — a new store added without a
corresponding isolation test fails CI rather than silently shipping
unscoped. `tests/isolation/test_live_stores.py` runs a live-container replay
(seeds two tenants, asserts cross-tenant reads never leak) and skips
gracefully when containers aren't available; `test_qdrant_isolation.py`
covers the offline assertions.

### 8.2 Credential vault

`CredentialVault` (Fernet AES-128-CBC + HMAC-SHA256) encrypts every
connector's `secret=True` schema field. Key rotation is supported via
`MultiFernet` (`AISOC_CREDENTIAL_KEY` + `AISOC_CREDENTIAL_KEY_ROTATION_FROM`).
The `api` service owns the encrypt/decrypt keypair authority; `connectors`
ships a vendored read-only `decrypt_dict()` so the poll-time scheduler can
decrypt without owning the write path. Vault tokens are versioned
(`vault:v1:<base64>`) so a future format change doesn't break existing
ciphertext.

### 8.3 Other hardening from the security wave

- **No `eval()`/`compile()` on untrusted input** anywhere — the rule engine's
  whitelisted AST parser (§4.2) replaced an earlier eval-based evaluator.
- **CORS** is vendored byte-identical across every Python service and
  actively refuses to boot if `AISOC_CORS_ORIGINS` contains `*` with
  credentials enabled in production.
- **LLM input contract** (`services/api/app/services/llm_safety.py`):
  untrusted content (threat-intel feed text, user-submitted strings) is
  sanitized (boundary markers, control-character stripping, length caps)
  before being concatenated into any prompt.
- **Prompt injection guard**: a per-run nonce ties detections to ledger
  flags and can force an `L0` demotion (i.e. strip autonomy) if injection is
  suspected mid-run.
- **Dev-mode unification**: one `AISOC_DEV_MODE` flag replaces a prior
  patchwork of per-service bypass flags; a CI gate asserts no dev-mode
  shortcut is reachable when unset in a production-like config.

---

## 9. Hunt workbench (`/hunt`)

Natural-language input is never sent straight to a data store as a raw
query. The flow (`apps/web/src/components/hunt/HuntView.tsx` →
`services/api/app/api/v1/endpoints/nl_query.py`):

```
1. User types a plain-English question.
2. nl_query.py resolves deterministic-first (routing analogous to §5.3):
   pattern-match against known query templates before ever invoking an LLM.
3. Whichever tier resolves it emits a TEMPLATE instantiation — an ES|QL, SPL,
   or KQL query built by filling parameters into a known-safe template — never
   a raw string the model free-formed. HuntAgent never writes raw queries.
4. The instantiated query executes against the tenant-scoped lake (§8.1).
5. Results support a "pivot" deep-link (pivotPath) into the graph/Investigation
   Rail for the matched entities.
```

Saved hunts (`saved_hunts.py`) persist the NL prompt + resolved template +
pivot path so a hunt can be re-run later without re-resolving the NL step.

---

## 10. Connector platform (`services/connectors`)

### 10.1 Registry contract

Every connector subclasses `BaseConnector` and is added to
`_CONNECTOR_CLASSES` in `services/connectors/app/connectors/__init__.py` —
adding a connector to that list is the entire wiring step; there is no
separate registration file to edit. Each declares:

- `schema()` → `ConnectorSchema(name, label, description, category, fields,
  oauth, default_poll_interval_seconds)` — drives the web console's connect
  form entirely from this one declaration.
- `capabilities()` → which of `PULL_ALERTS | PUSH_CASE | PUSH_STATUS |
  FEDERATED_SEARCH | …` this connector supports, inspected at runtime by the
  scheduler and by case fan-out.
- `normalize()` → collapses the vendor's native severity ladder into the
  platform's five tiers.

### 10.2 Scheduling algorithm

`ConnectorScheduler` (APScheduler) runs **in-process** inside the
`connectors` service — one job per enabled connector instance, default
5-minute cadence, overridable per-instance
(`connector_config.poll_interval_seconds`). The scheduler **reloads its job
list every 30 seconds**, so enabling/disabling a connector instance in the UI
takes effect without a service restart. Each poll cycle: decrypt credentials
(vendored vault read-path, §8.2) → fetch from the vendor API → `normalize()`
→ apply any tenant-defined filter rules → detect schema drift (vendor
changed their response shape) → push normalized events to `services/ingest`'s
batch endpoint with an `X-Tenant-ID` header → persist a checkpoint (so the
next poll resumes from where this one left off, not from the beginning).

### 10.3 Scale

Connector count is generated, not hand-maintained —
`scripts/generate_connector_count.py` is the source of truth and a CI gate
asserts the README's advertised count matches the registry's actual size.

---

## 11. Stateful stores — what each one is actually for

| Store | Primary role | Notes |
|---|---|---|
| **PostgreSQL** | System of record: alerts, cases, hunts, tenant config, credentials (encrypted), audit log | RLS + query-layer tenant filters (§8.1) |
| **Redis** | Fusion dedup fingerprint cache (§3.3), windowed-detection ZSETs (§3.4) | Also used for tenant-prefixed general caching |
| **Kafka** (Redpanda-compatible in CI, KRaft) | Ingest → fusion event backbone (`raw_events`, `vulnerability.matches` topics) | Tenant-tagged envelope, isolation-tested |
| **ClickHouse** | Tenant-scoped event lake for NL-hunt queries and ad-hoc analytics | `lake_sql.py` rewrites every query for tenant scoping |
| **Neo4j** | Entity graph written inline at ingest (§2.3); attack-path and blast-radius traversals | Tenant-scoped via node property + query filter |
| **Qdrant** | Vector store for threat-intel/actor embeddings (IOC similarity, actor attribution) | Public feed data is intentionally global; tenant-private vectors are scoped |

---

## 12. Where to go next

- [`llm-routing-and-gateway.md`](./llm-routing-and-gateway.md) — the two LLM
  call paths, the LiteLLM gateway, and the exact resolver algorithms.
- [`SYSTEM_DESIGN.md`](./SYSTEM_DESIGN.md) — historical framing: full
  connector-platform write-up, ITSM-as-projection design, Responder PWA, MCP
  server, one-click install.
- [`apps/docs/docs/concepts/model-router.md`](../../apps/docs/docs/concepts/model-router.md) — the escalation-ladder contract and its CI-gated determinism guarantee.
- [`apps/docs/docs/concepts/automation-maturity.md`](../../apps/docs/docs/concepts/automation-maturity.md) — the L0–L4 ladder definitions in full.
- [`docs/detections/truth-table.md`](../detections/truth-table.md) — executable vs. quarantined detection rule counts.
