"""
Aggregate metrics and quantile computations for Extended Shadow Mode.

Provides summary statistics, quantile calculations, and distribution breakdowns
from a list of shadow observations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np

from ml.shadow.models import DisagreementTaxonomy, ExtendedShadowObservation, ShadowStatus

logger = logging.getLogger(__name__)


class ShadowMetricsAggregator:
    """
    Computes operational summaries, quantiles, and invocation distributions.
    """

    @classmethod
    def compute_summary(cls, observations: List[ExtendedShadowObservation]) -> Dict[str, Any]:
        """
        Compute a comprehensive summary of shadow observations.

        Args:
            observations: List of ExtendedShadowObservation.

        Returns:
            Dictionary with metrics including counts, percentages, and latencies.
        """
        total = len(observations)
        if total == 0:
            return cls._empty_summary()

        successful = [o for o in observations if o.status == ShadowStatus.SUCCESS]
        n_succ = max(len(successful), 1)

        # Counts
        urlbert_count = sum(1 for o in successful if o.urlbert_invoked)
        onnx_count = sum(1 for o in successful if o.onnx_invoked)
        heuristics_count = sum(1 for o in successful if o.heuristics_resolved)
        hard_rules_count = sum(1 for o in successful if o.hard_rule_triggered)

        # Disagreements
        disagreements = [
            o for o in successful
            if o.disagreement_type != DisagreementTaxonomy.MATCH
        ]
        potential_fns = [
            o for o in successful
            if o.disagreement_type == DisagreementTaxonomy.PRODUCTION_MALICIOUS_CASCADE_SAFE
        ]

        # Latencies
        latencies = [o.total_latency_ms for o in successful if o.total_latency_ms > 0]
        if not latencies:
            latencies = [0.0]

        # Errors / Timeouts / Drops
        timeouts = sum(1 for o in observations if o.status == ShadowStatus.TIMEOUT)
        dropped = sum(1 for o in observations if o.status == ShadowStatus.DROPPED_CAPACITY)
        errors = sum(1 for o in observations if o.status == ShadowStatus.ERROR)

        # Compute quantiles
        def safe_percentile(arr, p):
            return float(np.percentile(arr, p)) if arr else 0.0

        p50 = safe_percentile(latencies, 50)
        p95 = safe_percentile(latencies, 95)
        p99 = safe_percentile(latencies, 99)
        mean = float(np.mean(latencies))

        return {
            "total_observations": total,
            "success_count": len(successful),
            "urlbert_invocation_pct": round((urlbert_count / n_succ) * 100.0, 2),
            "onnx_invocation_pct": round((onnx_count / n_succ) * 100.0, 2),
            "heuristic_resolution_pct": round((heuristics_count / n_succ) * 100.0, 2),
            "hard_rule_resolution_pct": round((hard_rules_count / n_succ) * 100.0, 2),
            "disagreement_pct": round((len(disagreements) / n_succ) * 100.0, 2),
            "potential_fn_count": len(potential_fns),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2),
            "mean_latency_ms": round(mean, 2),
            "error_pct": round((errors / total) * 100.0, 2),
            "timeout_pct": round((timeouts / total) * 100.0, 2),
            "dropped_capacity_pct": round((dropped / total) * 100.0, 2),
        }

    @classmethod
    def _empty_summary(cls) -> Dict[str, Any]:
        return {
            "total_observations": 0,
            "success_count": 0,
            "urlbert_invocation_pct": 0.0,
            "onnx_invocation_pct": 0.0,
            "heuristic_resolution_pct": 0.0,
            "hard_rule_resolution_pct": 0.0,
            "disagreement_pct": 0.0,
            "potential_fn_count": 0,
            "p50_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "p99_latency_ms": 0.0,
            "mean_latency_ms": 0.0,
            "error_pct": 0.0,
            "timeout_pct": 0.0,
            "dropped_capacity_pct": 0.0,
        }

    @classmethod
    def compute_disagreement_breakdown(
        cls,
        observations: List[ExtendedShadowObservation]
    ) -> Dict[str, int]:
        """Break down disagreements by category."""
        breakdown = {cat.value: 0 for cat in DisagreementTaxonomy}
        for o in observations:
            if o.disagreement_type != DisagreementTaxonomy.MATCH:
                breakdown[o.disagreement_type.value] = breakdown.get(o.disagreement_type.value, 0) + 1
        return breakdown

    @classmethod
    def compute_stage_distribution(
        cls,
        observations: List[ExtendedShadowObservation]
    ) -> Dict[str, int]:
        """Count how many observations reached each cascade stage."""
        stages = {}
        for o in observations:
            stage = o.stage_reached
            if isinstance(stage, str):
                stage_name = stage
            elif stage is not None and hasattr(stage, "value"):
                stage_name = stage.value
            else:
                stage_name = "UNKNOWN"
            stages[stage_name] = stages.get(stage_name, 0) + 1
        return stages