"""Compounding Memory — cross-investigation knowledge distillation.

Learns per-signature verdict priors from resolved investigations and
exposes a small, bounded confidence adjustment for Triage so that
recurring alert signatures are triaged faster over time.

Architecture notes
==================

* Uses AiSOC's existing institutional memory layer (``app.memory.institutional``)
  as the persistence backend — no new database tables or dependencies.
* All writes are best-effort (never raises); reads fall back to empty priors
  when the database is unavailable.
* ``distill()`` is a batch job intended to run on a schedule (cron / APScheduler
  via ``scripts/run_distillation.py``).  It re-reads all ``outcome:*`` keys
  from institutional memory and recomputes the signature priors.
* ``get_memory_verdict_adjustment()`` returns a bounded ±0.10 confidence nudge.
  It never overrides the LLM signal — it only biases triage toward historically
  reliable verdicts for well-known alert patterns.
* ``get_exemplars()`` returns investigation IDs of the highest-evidence resolved
  cases matching a signature, for future few-shot prompt injection.

Feature flag
============

``AISOC_COMPOUNDING_MEMORY_ENABLED`` (env, default ``1``).  Set to ``0`` to
disable all confidence adjustments (distillation still runs, but adjustments
return 0.0).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from app.memory.institutional import institutional_get, institutional_search, institutional_set

if TYPE_CHECKING:
    from app.models.state import InvestigationState

logger = structlog.get_logger()

# ---- Tunables (env-overridable) ----

# Minimum number of resolved investigations for a signature before the prior
# is trusted enough to produce a non-zero adjustment.
MIN_SAMPLES_FOR_ADJUSTMENT = int(os.getenv("AISOC_MEMORY_MIN_SAMPLES", "3"))

# Maximum absolute confidence adjustment (symmetrical).  A value of 0.10
# means priors can nudge confidence by at most ±10%.
MAX_ADJUSTMENT = float(os.getenv("AISOC_MEMORY_MAX_ADJUSTMENT", "0.10"))

# Number of exemplar investigation IDs to keep per signature.
DEFAULT_EXEMPLAR_BANK_SIZE = int(os.getenv("AISOC_MEMORY_EXEMPLAR_COUNT", "5"))

# Feature flag.
_ENABLED_FLAG = "AISOC_COMPOUNDING_MEMORY_ENABLED"


def _is_enabled() -> bool:
    raw = os.getenv(_ENABLED_FLAG)
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off", "disabled"}


# ---- Data models ----


def build_alert_signature(
    classification: str,
    tactic: str = "",
    technique: str = "",
) -> str:
    """Build a stable key for grouping investigations by alert type.

    The key is ``classification:tactic:technique`` (lowercased, empty parts
    omitted).  This matches the evidence-signature concept from the
    investigation pipeline — alerts with the same signature are assumed to
    represent the same underlying alert pattern.
    """
    parts = [
        p.strip().lower()
        for p in [classification or "", tactic or "", technique or ""]
        if p and p.strip()
    ]
    return ":".join(parts) if parts else "unknown"


def build_signature_for_state(state: InvestigationState, classification: str | None = None) -> str:
    """Build the compounding-memory alert signature for an InvestigationState.

    Centralises signature derivation so the write path (``outcomes.record_outcome``
    via the auto-triage worker) and the read path (triage / auto-triage confidence
    scoring) always agree on what counts as "the same alert pattern" — without
    this, adjustments written under one signature format would never be found by
    a lookup using a different one.

    ``classification`` lets a caller supply the most relevant label it already
    computed (e.g. the heuristic severity bucket, or the LLM verdict); falls
    back to ``raw_alert``'s own classification/category field, then "unknown".
    The tactic is derived from the first MITRE technique via the lightweight
    ``app.tools.mitre`` reference (best-effort; empty if unrecognised).
    """
    raw = state.raw_alert or {}
    cls = classification or str(raw.get("classification") or raw.get("category") or "unknown")

    techniques = state.mitre_mappings or raw.get("mitre_techniques") or []
    technique = str(techniques[0]) if techniques else ""

    tactic = ""
    if technique:
        try:
            from app.tools.mitre import lookup_technique  # noqa: PLC0415 — avoid import cycle

            base_id = technique.split(".")[0].upper()
            tactic_id = str(lookup_technique(base_id).get("tactic_id", "") or "")
            tactic = tactic_id if tactic_id != "Unknown" else ""
        except Exception:  # noqa: BLE001 — signature derivation is best-effort
            tactic = ""

    return build_alert_signature(cls, tactic, technique)


@dataclass
class SignaturePrior:
    """Distilled historical performance for one alert signature."""

    alert_signature: str
    total_count: int = 0
    false_positive_count: int = 0
    exemplar_investigation_ids: list[str] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.false_positive_count / self.total_count

    @property
    def prior_confidence(self) -> float:
        """1.0 = always confirmed incident; 0.0 = always false positive."""
        return max(0.0, min(1.0, 1.0 - self.false_positive_rate))


@dataclass
class DistillationReport:
    """Result of a single distillation pass."""

    signatures_processed: int
    priors: dict[str, SignaturePrior] = field(default_factory=dict)


# ---- Core class ----


class CompoundingMemory:
    """Learns per-signature verdict priors from resolved investigations.

    Usage::

        memory = CompoundingMemory()

        # During investigation resolution:
        await memory.record_verdict(tenant, signature, verdict, confidence, inv_id)

        # Nightly distillation job:
        report = await memory.distill(tenant_id)

        # During triage:
        adj = memory.get_memory_verdict_adjustment(signature)
        adjusted_confidence = raw_confidence + adj
    """

    def __init__(self) -> None:
        self._priors: dict[str, SignaturePrior] = {}
        # Tenant-scoped prior cache. distill() used to overwrite the single
        # flat ``_priors`` dict on every call, so distilling tenant B would
        # silently discard tenant A's priors (a cross-tenant leak risk once
        # this singleton is read from live, multi-tenant request paths).
        # ``_priors`` is kept for backward compatibility with callers that
        # don't scope by tenant (e.g. the single-tenant verify script);
        # tenant-aware callers must go through ``_tenant_priors`` via the
        # ``tenant_id`` parameter below.
        self._tenant_priors: dict[str, dict[str, SignaturePrior]] = {}
        self._last_distilled_at: dict[str, float] = {}

    async def record_verdict(
        self,
        tenant_id: str,
        alert_signature: str | None = None,
        verdict: str = "true_positive",
        confidence: float = 0.0,
        investigation_id: str | None = None,
        *,
        signature: str | None = None,
    ) -> None:
        """Write a resolved investigation's verdict into institutional memory.

        Best-effort — never raises.  Called by ``outcomes.record_outcome()``
        so every resolution feeds the distillation pipeline.
        """
        sig = alert_signature or signature or ""
        key = f"compounding:{sig}"
        try:
            existing = await institutional_get(tenant_id, key)
            if isinstance(existing, dict):
                entries = existing.get("entries", [])
            else:
                entries = []

            entries.append({
                "investigation_id": investigation_id or "",
                "verdict": verdict,
                "confidence": round(float(confidence or 0.0), 4),
            })
            # Keep the last 100 entries per signature to bound storage.
            entries = entries[-100:]

            await institutional_set(
                tenant_id,
                key,
                {"alert_signature": sig, "entries": entries},
                tags=["compounding_memory", sig],
            )
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.debug(
                "compounding_memory.record_verdict_failed",
                signature=str(sig).replace("\r", "").replace("\n", " ")[:200],
                error=str(exc).replace("\r", "").replace("\n", " ")[:200],
            )

    async def distill(self, tenant_id: str) -> DistillationReport:
        """Batch distillation: recompute per-signature priors from all recorded
        verdicts.  Intended to run on a schedule (nightly or more frequently).

        After this call, ``get_memory_verdict_adjustment()`` and
        ``get_exemplars()`` reflect the latest data.
        """
        priors: dict[str, SignaturePrior] = {}

        try:
            entries = await institutional_search(
                tenant_id, tags=["compounding_memory"], limit=500
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "compounding_memory.distill_search_failed",
                error=str(exc).replace("\r", "").replace("\n", " ")[:200],
            )
            self._priors = priors
            return DistillationReport(signatures_processed=0, priors=priors)

        for entry in entries:
            value = entry.get("value", {})
            if not isinstance(value, dict):
                continue
            sig = value.get("alert_signature", "")
            if not sig:
                continue

            prior = priors.setdefault(sig, SignaturePrior(alert_signature=sig))
            for rec in value.get("entries", []):
                prior.total_count += 1
                verdict_str = str(rec.get("verdict", "")).lower()
                if verdict_str in ("false_positive", "fp", "benign"):
                    prior.false_positive_count += 1
                inv_id = rec.get("investigation_id", "")
                if inv_id and len(prior.exemplar_investigation_ids) < DEFAULT_EXEMPLAR_BANK_SIZE:
                    prior.exemplar_investigation_ids.append(inv_id)

        self._priors = priors
        self._tenant_priors[tenant_id] = priors
        self._last_distilled_at[tenant_id] = time.time()
        logger.info(
            "compounding_memory.distill_complete",
            signatures_processed=len(priors),
            tenant_id=str(tenant_id).replace("\r", "").replace("\n", " ")[:80],
        )
        return DistillationReport(signatures_processed=len(priors), priors=priors)

    async def ensure_fresh(self, tenant_id: str, *, max_age_seconds: float = 300.0) -> None:
        """Distill ``tenant_id`` if it has never been distilled or its cached
        priors are older than ``max_age_seconds``. Lets live request paths
        (triage/auto-triage) call ``get_memory_verdict_adjustment`` without a
        separately-scheduled distillation job, while still bounding how often
        the (relatively expensive) institutional_search runs per tenant.
        """
        if not _is_enabled():
            return
        last = self._last_distilled_at.get(tenant_id)
        if last is not None and (time.time() - last) < max_age_seconds:
            return
        await self.distill(tenant_id)

    def get_memory_verdict_adjustment(self, alert_signature: str, tenant_id: str | None = None) -> float:
        """Return a bounded ±MAX_ADJUSTMENT confidence nudge for the given
        alert signature based on its historical false-positive rate.

        Returns 0.0 for unknown or insufficiently-seen signatures and when
        the feature is disabled via ``AISOC_COMPOUNDING_MEMORY_ENABLED=0``.
        When ``tenant_id`` is given, only that tenant's distilled priors are
        consulted (never falls back to another tenant's cache); when omitted,
        the legacy flat (last-distilled-tenant) cache is used, matching prior
        single-tenant callers.
        """
        if not _is_enabled():
            return 0.0

        priors = self._tenant_priors.get(tenant_id, {}) if tenant_id is not None else self._priors
        prior = priors.get(alert_signature)
        if not prior or prior.total_count < MIN_SAMPLES_FOR_ADJUSTMENT:
            return 0.0

        # prior_confidence 1.0 (always confirmed) → +MAX; 0.0 (always FP) → -MAX; 0.5 → 0.0
        adjustment = (prior.prior_confidence - 0.5) * (2 * MAX_ADJUSTMENT)
        return max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, round(adjustment, 4)))

    def get_adjustment(
        self,
        alert_signature: str,
        current_confidence: float = 0.0,
        tenant_id: str | None = None,
    ) -> float:
        """Return confidence adjusted by historical verdict prior."""
        nudge = self.get_memory_verdict_adjustment(alert_signature, tenant_id=tenant_id)
        return max(0.0, min(1.0, round(current_confidence + nudge, 4)))

    def get_exemplars(self, alert_signature: str, tenant_id: str | None = None) -> list[str]:
        """Return up to DEFAULT_EXEMPLAR_BANK_SIZE investigation IDs for the
        most evidenced resolved cases matching this signature.

        Intended for few-shot prompt injection in future triage prompts.
        """
        priors = self._tenant_priors.get(tenant_id, {}) if tenant_id is not None else self._priors
        prior = priors.get(alert_signature)
        return list(prior.exemplar_investigation_ids) if prior else []

    def list_priors(self) -> list[SignaturePrior]:
        """Return every currently-distilled signature prior (read-only)."""
        return list(self._priors.values())

    def clear(self) -> None:
        """Clear in-memory priors (test isolation helper)."""
        self._priors = {}
        self._tenant_priors = {}
        self._last_distilled_at = {}


# Module-level singleton.
compounding_memory = CompoundingMemory()
