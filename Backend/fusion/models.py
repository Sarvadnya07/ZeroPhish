"""
Data Models for ZeroPhish Detection Fusion
==========================================
Defines canonical evidence, source authority, tier summaries, and explainability.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class EvidenceSource(str, Enum):
    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3 = "tier3"
    VISION = "vision"
    CLIENT_ADVISORY = "client_advisory"


class EvidenceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthorityLevel(str, Enum):
    AUTHORITATIVE = "authoritative"
    ADVISORY = "advisory"


class CanonicalEvidence(BaseModel):
    """
    Normalized, typed security evidence item with explicit source and authority.
    """
    model_config = ConfigDict(extra="ignore")

    source_tier: EvidenceSource = Field(..., description="Originating tier of this evidence")
    signal_type: str = Field(..., min_length=1, description="Standardized signal identifier")
    description: str = Field(..., min_length=1, description="Human-readable evidence summary")
    severity: EvidenceSeverity = Field(default=EvidenceSeverity.INFO, description="Risk severity of this signal")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this specific signal")
    authoritative: bool = Field(default=False, description="True if evidence is deterministic/authoritative")
    provenance: str = Field(default="system", description="Specific mechanism or model that produced evidence")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary structured context")


class TierExecutionSummary(BaseModel):
    """
    Summary of an individual tier's execution and contribution to the final verdict.
    """
    model_config = ConfigDict(extra="ignore")

    tier: str = Field(..., description="Tier identifier (tier1, tier2, tier3, vision)")
    status: str = Field(..., description="Lifecycle status: complete, failed, timeout, not_requested, degraded")
    score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Raw score produced by tier, if successful")
    weight: float = Field(default=0.0, ge=0.0, le=1.0, description="Weight contributed in the final fused score")
    authoritative: bool = Field(default=False, description="Whether tier is authoritative or advisory")
    participated: bool = Field(default=False, description="Whether tier score participated in weighted fusion")
    reason: Optional[str] = Field(None, description="Diagnostic explanation if tier failed or did not participate")
    requires_followup: bool = Field(default=False, description="Indicates manual inspection or missing screenshot follow-up needed")


class FusionExplanation(BaseModel):

    """
    Structured explainability report answering why the scan reached its verdict.
    """
    model_config = ConfigDict(extra="ignore")

    verdict: str = Field(..., description="Final security verdict (SAFE, SUSPICIOUS, CRITICAL, UNKNOWN)")
    final_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Final fused risk score")
    top_reasons: List[str] = Field(default_factory=list, description="Top human-readable reasons for verdict")
    contributing_evidence: List[CanonicalEvidence] = Field(
        default_factory=list,
        description="Key evidence items driving the verdict",
    )
    tier_summaries: Dict[str, TierExecutionSummary] = Field(
        default_factory=dict,
        description="Execution status and weights of each tier",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit notice of missing, failed, or timed-out tiers",
    )


class FusionResult(BaseModel):
    """
    Authoritative output of the detection fusion engine.
    """
    model_config = ConfigDict(extra="ignore")

    partial_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Authoritative server partial score")
    final_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Final fused multi-tier score")
    verdict: str = Field(..., description="Final canonical verdict")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Coverage/evidence certainty score")
    is_degraded: bool = Field(default=False, description="True if one or more tiers failed or were unavailable")
    canonical_evidence: List[CanonicalEvidence] = Field(default_factory=list, description="All normalized evidence items")
    combined_evidence_strings: List[str] = Field(
        default_factory=list,
        description="Flattened deduplicated string list for backward compatibility",
    )
    explanation: FusionExplanation = Field(..., description="Structured explanation of the verdict")
