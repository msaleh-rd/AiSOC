"""Configurable causal scoring factors for the PageRank RCA engine.

Each factor is a multiplier applied during root-cause scoring.  All values
are env-overridable so operators can tune the scoring without code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class CausalFactors:
    """Tuneable weights for the causal scoring algorithm."""

    # Topology position multipliers
    direct_dependency_boost: float = 1.5      # service is a direct upstream dependency
    transitive_dependency_boost: float = 1.2  # service is 2 hops upstream
    distant_dependency_factor: float = 1.0    # service is 3+ hops upstream
    target_service_penalty: float = 0.3       # the target itself is penalised as root cause
    not_in_path_factor: float = 0.8           # service has anomalies but isn't upstream

    # Temporal ordering factors
    temporal_early_boost: float = 1.5         # anomaly appeared well before the target
    temporal_moderate_boost: float = 1.2      # anomaly appeared shortly before the target
    temporal_late_boost: float = 0.7          # anomaly appeared after the target (reactive)
    temporal_threshold_seconds: float = 300.0 # boundary between "well before" and "shortly before"

    # Criticality
    criticality_multiplier: float = 0.1       # per-dependent criticality bonus


def load_causal_factors() -> CausalFactors:
    """Load causal factors from environment variables (with defaults)."""
    return CausalFactors(
        direct_dependency_boost=float(os.getenv("AISOC_RCA_DIRECT_BOOST", "1.5")),
        transitive_dependency_boost=float(os.getenv("AISOC_RCA_TRANSITIVE_BOOST", "1.2")),
        distant_dependency_factor=float(os.getenv("AISOC_RCA_DISTANT_FACTOR", "1.0")),
        target_service_penalty=float(os.getenv("AISOC_RCA_TARGET_PENALTY", "0.3")),
        not_in_path_factor=float(os.getenv("AISOC_RCA_NOT_IN_PATH", "0.8")),
        temporal_early_boost=float(os.getenv("AISOC_RCA_TEMPORAL_EARLY", "1.5")),
        temporal_moderate_boost=float(os.getenv("AISOC_RCA_TEMPORAL_MODERATE", "1.2")),
        temporal_late_boost=float(os.getenv("AISOC_RCA_TEMPORAL_LATE", "0.7")),
        temporal_threshold_seconds=float(os.getenv("AISOC_RCA_TEMPORAL_THRESHOLD", "300.0")),
        criticality_multiplier=float(os.getenv("AISOC_RCA_CRITICALITY_MULT", "0.1")),
    )
