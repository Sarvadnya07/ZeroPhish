"""
Data models and taxonomy for Extended Cascade Shadow Evaluation.

Defines the core enums (disagreement types, shadow status) and Pydantic
models for observation records and rollout gate results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------- Enums ----------
class DisagreementTaxonomy(str, Enum):
    """Categorisation of disagreements between production verdict and cascade verdict."""
    MATCH = "MATCH"
    PRODUCTION_SAFE_CASCADE_MALICIOUS = "PRODUCTION_SAFE_CASCADE_MALICIOUS"
    PRODUCTION_SAFE_CASCADE_SUSPICIOUS = "PRODUCTION_SAFE_CASCADE_SUSPICIOUS"
    PRODUCTION_SUSPICIOUS_CASCADE_SAFE = "PRODUCTION_SUSPICIOUS_CASCADE_SAFE"
    PRODUCTION_SUSPICIOUS_CASCADE_MALICIOUS = "PRODUCTION_SUSPICIOUS_CASCADE_MALICIOUS"
    PRODUCTION_MALICIOUS_CASCADE_SAFE = "PRODUCTION_MALICIOUS_CASCADE_SAFE"  # Critical Potential FN
    PRODUCTION_MALICIOUS_CASCADE_SUSPICIOUS = "PRODUCTION_MALICIOUS_CASCADE_SUSPICIOUS"
    OTHER = "OTHER"


class ShadowStatus(str, Enum):
    """Status of a shadow observation attempt."""
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    DROPPED_CAPACITY = "DROPPED_CAPACITY"
    ERROR = "ERROR"
    SKIPPED_SAMPLING = "SKIPPED_SAMPLING"


# ---------- Models ----------
class ExtendedShadowObservation(BaseModel):
    """
    Comprehensive observation record for shadow cascade evaluation.

    Includes provenance, timing breakdown, and disagreement classification.
    """
    observation_id: str = Field(..., min_length=1)
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    environment: str = Field(default="staging", description="Environment tag")
    data_provenance: str = Field(
        default="REAL_STAGING",
        description="Data source: REAL_STAGING | BENCHMARK_REPLAY | SYNTHETIC_TEST"
    )
    sample_rate: float = Field(..., ge=0.0, le=1.0)
    production_verdict: str
    production_score: float = Field(..., ge=0.0, le=100.0)
    cascade_verdict: Optional[str] = None
    cascade_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    stage_reached: Optional[str] = None
    heuristics_resolved: bool = False
    onnx_invoked: bool = False
    urlbert_invoked: bool = False
    hard_rule_triggered: bool = False
    model_health: str = "MODEL_READY"
    status: ShadowStatus
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    preprocessing_ms: float = Field(default=0.0, ge=0.0)
    heuristic_ms: float = Field(default=0.0, ge=0.0)
    onnx_ms: float = Field(default=0.0, ge=0.0)
    urlbert_ms: float = Field(default=0.0, ge=0.0)
    fusion_ms: float = Field(default=0.0, ge=0.0)
    semaphore_wait_ms: float = Field(default=0.0, ge=0.0)
    total_wall_ms: float = Field(default=0.0, ge=0.0)
    is_cold_start: bool = False
    disagreement_type: DisagreementTaxonomy = DisagreementTaxonomy.MATCH
    security_override: Optional[str] = None
    url_hash: str = Field(..., min_length=64, max_length=64)
    hostname_hash: str = Field(..., min_length=64, max_length=64)

    @field_validator("url_hash", "hostname_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if not v or len(v) != 64 or not all(c in "0123456789abcdef" for c in v.lower()):
            raise ValueError("Hash must be a 64-character hex string")
        return v

    @field_validator("production_verdict", "cascade_verdict")
    @classmethod
    def validate_verdict(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"SAFE", "SUSPICIOUS", "CRITICAL", "MALICIOUS"}
            if v.upper() not in allowed:
                raise ValueError(f"Verdict must be one of {allowed}, got {v}")
        return v


class RolloutGateResult(BaseModel):
    """Result of a shadow rollout gate evaluation."""
    stage: str = Field(..., description="Rollout stage identifier")
    sample_rate: float = Field(..., ge=0.0, le=1.0)
    observations_count: int = Field(..., ge=0)
    gate_passed: bool
    urlbert_invocation_pct: float = Field(..., ge=0.0, le=100.0)
    onnx_invocation_pct: float = Field(..., ge=0.0, le=100.0)
    heuristic_resolution_pct: float = Field(..., ge=0.0, le=100.0)
    disagreement_pct: float = Field(..., ge=0.0, le=100.0)
    potential_fn_count: int = Field(..., ge=0)
    p95_latency_ms: float = Field(..., ge=0.0)
    error_pct: float = Field(..., ge=0.0, le=100.0)
    reasons: List[str] = Field(default_factory=list)