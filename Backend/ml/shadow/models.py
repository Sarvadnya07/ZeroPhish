"""
Data models and taxonomy for Extended Cascade Shadow Evaluation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DisagreementTaxonomy(str, Enum):
    MATCH = "MATCH"
    PRODUCTION_SAFE_CASCADE_MALICIOUS = "PRODUCTION_SAFE_CASCADE_MALICIOUS"
    PRODUCTION_SAFE_CASCADE_SUSPICIOUS = "PRODUCTION_SAFE_CASCADE_SUSPICIOUS"
    PRODUCTION_SUSPICIOUS_CASCADE_SAFE = "PRODUCTION_SUSPICIOUS_CASCADE_SAFE"
    PRODUCTION_SUSPICIOUS_CASCADE_MALICIOUS = "PRODUCTION_SUSPICIOUS_CASCADE_MALICIOUS"
    PRODUCTION_MALICIOUS_CASCADE_SAFE = "PRODUCTION_MALICIOUS_CASCADE_SAFE"  # Critical Potential FN
    PRODUCTION_MALICIOUS_CASCADE_SUSPICIOUS = "PRODUCTION_MALICIOUS_CASCADE_SUSPICIOUS"
    OTHER = "OTHER"


class ShadowStatus(str, Enum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    DROPPED_CAPACITY = "DROPPED_CAPACITY"
    ERROR = "ERROR"
    SKIPPED_SAMPLING = "SKIPPED_SAMPLING"


class ExtendedShadowObservation(BaseModel):
    observation_id: str
    timestamp: str
    environment: str = "staging"
    sample_rate: float
    production_verdict: str
    production_score: float
    cascade_verdict: Optional[str] = None
    cascade_score: Optional[float] = None
    stage_reached: Optional[str] = None
    heuristics_resolved: bool = False
    onnx_invoked: bool = False
    urlbert_invoked: bool = False
    hard_rule_triggered: bool = False
    model_health: str = "MODEL_READY"
    status: ShadowStatus
    total_latency_ms: float = 0.0
    onnx_latency_ms: float = 0.0
    urlbert_latency_ms: float = 0.0
    disagreement_type: DisagreementTaxonomy = DisagreementTaxonomy.MATCH
    security_override: Optional[str] = None
    url_hash: str
    hostname_hash: str


class RolloutGateResult(BaseModel):
    stage: str
    sample_rate: float
    observations_count: int
    gate_passed: bool
    urlbert_invocation_pct: float
    onnx_invocation_pct: float
    heuristic_resolution_pct: float
    disagreement_pct: float
    potential_fn_count: int
    p95_latency_ms: float
    error_pct: float
    reasons: List[str]
