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
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.memory.institutional import institutional_get, institutional_search, institutional_set

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
        logger.info(
            "compounding_memory.distill_complete",
            signatures_processed=len(priors),
            tenant_id=str(tenant_id).replace("\r", "").replace("\n", " ")[:80],
        )
        return DistillationReport(signatures_processed=len(priors), priors=priors)

    def get_memory_verdict_adjustment(self, alert_signature: str) -> float:
        """Return a bounded ±MAX_ADJUSTMENT confidence nudge for the given
        alert signature based on its historical false-positive rate.

        Returns 0.0 for unknown or insufficiently-seen signatures and when
        the feature is disabled via ``AISOC_COMPOUNDING_MEMORY_ENABLED=0``.
        """
        if not _is_enabled():
            return 0.0

        prior = self._priors.get(alert_signature)
        if not prior or prior.total_count < MIN_SAMPLES_FOR_ADJUSTMENT:
            return 0.0

        # prior_confidence 1.0 (always confirmed) → +MAX; 0.0 (always FP) → -MAX; 0.5 → 0.0
        adjustment = (prior.prior_confidence - 0.5) * (2 * MAX_ADJUSTMENT)
        return max(-MAX_ADJUSTMENT, min(MAX_ADJUSTMENT, round(adjustment, 4)))

    def get_adjustment(
        self,
        alert_signature: str,
        current_confidence: float = 0.0,
    ) -> float:
        """Return confidence adjusted by historical verdict prior."""
        nudge = self.get_memory_verdict_adjustment(alert_signature)
        return max(0.0, min(1.0, round(current_confidence + nudge, 4)))

    def get_exemplars(self, alert_signature: str) -> list[str]:
        """Return up to DEFAULT_EXEMPLAR_BANK_SIZE investigation IDs for the
        most evidenced resolved cases matching this signature.

        Intended for few-shot prompt injection in future triage prompts.
        """
        prior = self._priors.get(alert_signature)
        return list(prior.exemplar_investigation_ids) if prior else []

    def list_priors(self) -> list[SignaturePrior]:
        """Return every currently-distilled signature prior (read-only)."""
        return list(self._priors.values())

    def clear(self) -> None:
        """Clear in-memory priors (test isolation helper)."""
        self._priors = {}


# Module-level singleton.
compounding_memory = CompoundingMemory()
