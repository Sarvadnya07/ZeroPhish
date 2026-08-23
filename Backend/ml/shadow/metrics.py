"""
Aggregate metrics and quantile computations for Extended Shadow Mode.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import numpy as np

from ml.shadow.models import DisagreementTaxonomy, ExtendedShadowObservation, ShadowStatus

logger = logging.getLogger(__name__)


class ShadowMetricsAggregator:
    """Computes operational summaries, quantiles, and invocation distributions."""

    @classmethod
    def compute_summary(cls, observations: List[ExtendedShadowObservation]) -> Dict[str, Any]:
        total = len(observations)
        if total == 0:
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
                "error_pct": 0.0,
                "timeout_pct": 0.0,
                "dropped_capacity_pct": 0.0,
            }

        successful = [o for o in observations if o.status == ShadowStatus.SUCCESS]
        n_succ = max(len(successful), 1)

        urlbert_count = sum(1 for o in successful if o.urlbert_invoked)
        onnx_count = sum(1 for o in successful if o.onnx_invoked)
        heuristics_count = sum(1 for o in successful if o.heuristics_resolved)
        hard_rules_count = sum(1 for o in successful if o.hard_rule_triggered)

        disagreements = [o for o in successful if o.disagreement_type != DisagreementTaxonomy.MATCH]
        potential_fns = [
            o
            for o in successful
            if o.disagreement_type == DisagreementTaxonomy.PRODUCTION_MALICIOUS_CASCADE_SAFE
        ]

        latencies = [o.total_latency_ms for o in successful] or [0.0]

        timeouts = sum(1 for o in observations if o.status == ShadowStatus.TIMEOUT)
        dropped = sum(1 for o in observations if o.status == ShadowStatus.DROPPED_CAPACITY)
        errors = sum(1 for o in observations if o.status == ShadowStatus.ERROR)

        return {
            "total_observations": total,
            "success_count": len(successful),
            "urlbert_invocation_pct": round((urlbert_count / n_succ) * 100.0, 2),
            "onnx_invocation_pct": round((onnx_count / n_succ) * 100.0, 2),
            "heuristic_resolution_pct": round((heuristics_count / n_succ) * 100.0, 2),
            "hard_rule_resolution_pct": round((hard_rules_count / n_succ) * 100.0, 2),
            "disagreement_pct": round((len(disagreements) / n_succ) * 100.0, 2),
            "potential_fn_count": len(potential_fns),
            "p50_latency_ms": round(float(np.percentile(latencies, 50)), 2),
            "p95_latency_ms": round(float(np.percentile(latencies, 95)), 2),
            "p99_latency_ms": round(float(np.percentile(latencies, 99)), 2),
            "error_pct": round((errors / total) * 100.0, 2),
            "timeout_pct": round((timeouts / total) * 100.0, 2),
            "dropped_capacity_pct": round((dropped / total) * 100.0, 2),
        }
