"""Tests for compounding memory — cross-investigation knowledge distillation."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from app.memory.distillation import (
    CompoundingMemory,
    DistillationReport,
    SignaturePrior,
    build_alert_signature,
    build_signature_for_state,
    compounding_memory,
)


class TestBuildAlertSignature:
    def test_full_signature(self) -> None:
        assert build_alert_signature("Malware", "Execution", "T1059") == "malware:execution:t1059"

    def test_empty_parts_omitted(self) -> None:
        assert build_alert_signature("Phishing", "", "") == "phishing"

    def test_all_empty(self) -> None:
        assert build_alert_signature("", "", "") == "unknown"

    def test_whitespace_stripped(self) -> None:
        assert build_alert_signature("  Lateral Movement ", " T1021 ", "") == "lateral movement:t1021"


class TestSignaturePrior:
    def test_fp_rate_zero_when_no_fps(self) -> None:
        p = SignaturePrior(alert_signature="test", total_count=10, false_positive_count=0)
        assert p.false_positive_rate == 0.0
        assert p.prior_confidence == 1.0

    def test_fp_rate_half(self) -> None:
        p = SignaturePrior(alert_signature="test", total_count=10, false_positive_count=5)
        assert p.false_positive_rate == 0.5
        assert p.prior_confidence == 0.5

    def test_fp_rate_all_fp(self) -> None:
        p = SignaturePrior(alert_signature="test", total_count=10, false_positive_count=10)
        assert p.false_positive_rate == 1.0
        assert p.prior_confidence == 0.0

    def test_empty_counts(self) -> None:
        p = SignaturePrior(alert_signature="test")
        assert p.false_positive_rate == 0.0
        assert p.prior_confidence == 1.0


class TestCompoundingMemory:
    def setup_method(self) -> None:
        self.memory = CompoundingMemory()

    def test_adjustment_unknown_signature(self) -> None:
        """Unknown signatures should produce zero adjustment."""
        assert self.memory.get_memory_verdict_adjustment("unknown:sig") == 0.0

    def test_adjustment_insufficient_samples(self) -> None:
        """Signatures with too few samples should produce zero adjustment."""
        self.memory._priors["test:sig"] = SignaturePrior(
            alert_signature="test:sig", total_count=2, false_positive_count=2
        )
        # 2 < MIN_SAMPLES (3), so no adjustment
        assert self.memory.get_memory_verdict_adjustment("test:sig") == 0.0

    def test_adjustment_all_confirmed(self) -> None:
        """Signatures that are always confirmed incidents → positive adjustment."""
        self.memory._priors["test:sig"] = SignaturePrior(
            alert_signature="test:sig", total_count=10, false_positive_count=0
        )
        adj = self.memory.get_memory_verdict_adjustment("test:sig")
        assert adj > 0
        assert adj <= 0.10

    def test_adjustment_all_fp(self) -> None:
        """Signatures that are always false positives → negative adjustment."""
        self.memory._priors["test:sig"] = SignaturePrior(
            alert_signature="test:sig", total_count=10, false_positive_count=10
        )
        adj = self.memory.get_memory_verdict_adjustment("test:sig")
        assert adj < 0
        assert adj >= -0.10

    def test_adjustment_balanced(self) -> None:
        """50/50 signatures → zero adjustment."""
        self.memory._priors["test:sig"] = SignaturePrior(
            alert_signature="test:sig", total_count=10, false_positive_count=5
        )
        assert self.memory.get_memory_verdict_adjustment("test:sig") == 0.0

    def test_exemplars_empty_for_unknown(self) -> None:
        assert self.memory.get_exemplars("unknown") == []

    def test_exemplars_populated(self) -> None:
        self.memory._priors["test:sig"] = SignaturePrior(
            alert_signature="test:sig",
            exemplar_investigation_ids=["inv-1", "inv-2"],
        )
        assert self.memory.get_exemplars("test:sig") == ["inv-1", "inv-2"]

    def test_list_priors(self) -> None:
        self.memory._priors["a"] = SignaturePrior(alert_signature="a", total_count=5)
        self.memory._priors["b"] = SignaturePrior(alert_signature="b", total_count=3)
        assert len(self.memory.list_priors()) == 2

    def test_clear(self) -> None:
        self.memory._priors["a"] = SignaturePrior(alert_signature="a")
        self.memory.clear()
        assert len(self.memory._priors) == 0

    @pytest.mark.asyncio
    async def test_record_verdict_and_distill(self) -> None:
        """End-to-end test: record verdicts then distill priors.

        Uses the in-memory fallback path (no database), so institutional_get/set
        fall back to dict storage.
        """
        tenant = "test-tenant"
        sig = "malware:execution:t1059"

        # Record several verdicts
        for i in range(5):
            await self.memory.record_verdict(
                tenant, sig, verdict="true_positive", confidence=0.9, investigation_id=f"inv-{i}"
            )
        # Record some FPs
        for i in range(5, 8):
            await self.memory.record_verdict(
                tenant, sig, verdict="false_positive", confidence=0.8, investigation_id=f"inv-{i}"
            )

        # Distill
        report = await self.memory.distill(tenant)
        assert isinstance(report, DistillationReport)
        # The in-memory fallback for institutional_search may return results
        # depending on whether the institutional layer has a database; if
        # running without postgres the priors will be empty (expected).
        # This test validates the code paths don't crash.


class TestTenantScopedPriors:
    """Regression tests for the tenant-isolation fix in distill()/adjustment
    lookups — distill() used to overwrite a single flat cache on every call,
    so distilling tenant B silently discarded tenant A's priors."""

    def setup_method(self) -> None:
        self.memory = CompoundingMemory()

    def test_tenant_scoped_adjustment_does_not_leak_across_tenants(self) -> None:
        sig = "malware:execution:t1059"
        self.memory._tenant_priors["tenant-a"] = {
            sig: SignaturePrior(alert_signature=sig, total_count=10, false_positive_count=10),
        }
        self.memory._tenant_priors["tenant-b"] = {
            sig: SignaturePrior(alert_signature=sig, total_count=10, false_positive_count=0),
        }

        adj_a = self.memory.get_memory_verdict_adjustment(sig, tenant_id="tenant-a")
        adj_b = self.memory.get_memory_verdict_adjustment(sig, tenant_id="tenant-b")
        assert adj_a < 0  # all false positives for tenant A
        assert adj_b > 0  # all confirmed for tenant B

        # A tenant with no distilled priors at all must never fall back to
        # another tenant's cache.
        assert self.memory.get_memory_verdict_adjustment(sig, tenant_id="tenant-c") == 0.0

    @pytest.mark.asyncio
    async def test_distill_does_not_clobber_other_tenants(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """distill(tenant_b) must not erase tenant_a's already-distilled priors."""
        sig = "malware:execution:t1059"

        async def _fake_search(tenant_id, **kwargs):  # noqa: ANN001, ARG001
            entries = {
                "tenant-a": [{"value": {"alert_signature": sig, "entries": [{"verdict": "true_positive"}] * 5}}],
                "tenant-b": [{"value": {"alert_signature": sig, "entries": [{"verdict": "false_positive"}] * 5}}],
            }
            return entries.get(tenant_id, [])

        import app.memory.distillation as distillation_module

        monkeypatch.setattr(distillation_module, "institutional_search", _fake_search)

        await self.memory.distill("tenant-a")
        await self.memory.distill("tenant-b")

        assert self.memory._tenant_priors["tenant-a"][sig].false_positive_count == 0
        assert self.memory._tenant_priors["tenant-b"][sig].false_positive_count == 5


@pytest.mark.asyncio
async def test_repeated_false_positive_signature_lowers_live_triage_confidence():
    """End-to-end: a well-established false-positive prior for a signature
    must lower confidence when ``run_triage()`` executes for a new alert with
    that same signature — proves the read path is actually wired into live
    triage (app.agents.triage_agent), not just unit-testable in isolation."""
    from app.agents.triage_agent import run_triage
    from app.models.state import InvestigationState

    def _make_state(tenant_id) -> InvestigationState:
        return InvestigationState(
            incident_id=uuid4(),
            tenant_id=tenant_id,
            alert_summary="Suspicious login anomaly detected",
            raw_alert={"hostname": "host-01", "mitre_techniques": ["T1078"]},
        )

    tenant_id = uuid4()

    baseline_state = await run_triage(_make_state(tenant_id))
    baseline_confidence = baseline_state.confidence

    signature = build_signature_for_state(baseline_state, classification="high")
    compounding_memory._tenant_priors[str(tenant_id)] = {
        signature: SignaturePrior(alert_signature=signature, total_count=10, false_positive_count=10),
    }
    compounding_memory._last_distilled_at[str(tenant_id)] = time.time()

    try:
        adjusted_state = await run_triage(_make_state(tenant_id))
    finally:
        compounding_memory._tenant_priors.pop(str(tenant_id), None)
        compounding_memory._last_distilled_at.pop(str(tenant_id), None)

    assert any("Compounding memory" in b for b in adjusted_state.confidence_basis)
    assert adjusted_state.confidence < baseline_confidence
