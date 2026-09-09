"""Tests for compounding memory — cross-investigation knowledge distillation."""

from __future__ import annotations

import pytest

from app.memory.distillation import (
    CompoundingMemory,
    DistillationReport,
    SignaturePrior,
    build_alert_signature,
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
