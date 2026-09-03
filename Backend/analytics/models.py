"""
Analytics models — heatmaps, threat feed, model metrics, false-positive records.

These Pydantic models define the canonical data contracts for all analytics,
telemetry, and administrative operations across the ZeroPhish platform.
They are used both by the gateway (for aggregations) and by the frontend.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------- Enums for type safety ----------
class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ConditionType(str, Enum):
    SCORE_THRESHOLD = "score_threshold"
    SENDER_DOMAIN = "sender_domain"
    KEYWORD = "keyword"
    TLD = "tld"


class PolicyAction(str, Enum):
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    ALLOW = "allow"


# ---------- Models ----------
class ThreatHeatmapEntry(BaseModel):
    """Aggregated threat data for a specific hour and day of the week."""
    hour: int = Field(..., ge=0, le=23, description="Hour of day (0-23)")
    day: int = Field(..., ge=0, le=6, description="Day of week (0=Monday, 6=Sunday)")
    count: int = Field(..., ge=0, description="Number of scans in this slot")
    avg_score: float = Field(..., ge=0.0, le=100.0, description="Average threat score for this slot")

    @field_validator("hour", "day")
    @classmethod
    def validate_range(cls, v: int, info) -> int:
        if info.field_name == "hour" and not (0 <= v <= 23):
            raise ValueError(f"hour must be between 0 and 23, got {v}")
        if info.field_name == "day" and not (0 <= v <= 6):
            raise ValueError(f"day must be between 0 and 6, got {v}")
        return v


class ThreatFeedItem(BaseModel):
    """A single entry in the real-time threat feed."""
    id: str = Field(..., min_length=1, description="Unique feed item identifier")
    timestamp: datetime = Field(..., description="ISO-8601 timestamp of the scan")
    sender_domain: str = Field(..., min_length=1, description="Domain of the email sender")
    subject_snippet: str = Field(..., max_length=100, description="First 100 chars of the email subject")
    final_score: float = Field(..., ge=0.0, le=100.0, description="Aggregated threat score")
    verdict: Verdict = Field(..., description="Final threat classification")
    category: str = Field(..., description="Threat category (e.g., BEC, Credential, Safe)")
    tier1_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    tier2_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    tier3_score: Optional[float] = Field(None, ge=0.0, le=100.0)


class ModelMetrics(BaseModel):
    """Performance metrics of the ML model used in Tier 2."""
    model_id: str = Field(..., description="HuggingFace model ID or custom name")
    accuracy: float = Field(..., ge=0.0, le=1.0)
    precision: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1: float = Field(..., ge=0.0, le=1.0)
    total_inferences: int = Field(..., ge=0)
    avg_latency_ms: float = Field(..., ge=0.0)
    false_positive_rate: float = Field(..., ge=0.0, le=1.0)
    false_negative_rate: float = Field(..., ge=0.0, le=1.0)
    last_evaluated: datetime = Field(..., description="When these metrics were computed")


class FalsePositiveReport(BaseModel):
    """User-submitted false-positive report for a scan."""
    id: str = Field(..., min_length=1)
    scan_id: str = Field(..., min_length=1)
    reporter_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1, description="Why the user believes this was a false positive")
    original_score: float = Field(..., ge=0.0, le=100.0)
    original_verdict: Verdict
    created_at: datetime
    reviewed: bool = False
    reviewer_id: Optional[str] = None
    resolution: Optional[str] = None


class PolicyRule(BaseModel):
    """A security policy rule that defines an action based on a condition."""
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: str = ""
    enabled: bool = True
    condition_type: ConditionType
    condition_value: str = Field(..., min_length=1)
    action: PolicyAction
    created_by: str = Field(..., min_length=1)
    created_at: datetime


class PolicyRuleCreate(BaseModel):
    """Payload for creating a new policy rule."""
    name: str = Field(..., min_length=1)
    description: str = ""
    condition_type: ConditionType
    condition_value: str = Field(..., min_length=1)
    action: PolicyAction
    enabled: bool = True


class AdminDashboardSummary(BaseModel):
    """High-level summary for the admin dashboard."""
    total_scans_today: int = Field(..., ge=0)
    total_scans_week: int = Field(..., ge=0)
    critical_today: int = Field(..., ge=0)
    suspicious_today: int = Field(..., ge=0)
    safe_today: int = Field(..., ge=0)
    avg_score_today: float = Field(..., ge=0.0, le=100.0)
    false_positives_pending: int = Field(..., ge=0)
    open_incidents: int = Field(..., ge=0)
    circuit_breaker_state: str = Field(..., description="CLOSED, OPEN, or HALF_OPEN")
    top_malicious_domains: list[dict[str, Any]] = Field(default_factory=list)
    top_senders: list[dict[str, Any]] = Field(default_factory=list)
    model_accuracy: float = Field(..., ge=0.0, le=1.0)