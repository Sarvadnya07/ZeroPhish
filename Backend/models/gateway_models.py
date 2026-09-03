"""
Shared data models for ZeroPhish Gateway.

Defines the request/response schemas for the multi‑tier phishing detection pipeline,
including Tier 1 (client), Tier 2 (metadata/ML), and Tier 3 (AI) results.
All models include validation and are fully type‑annotated.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, EmailStr, field_validator

# ---------- Enums ----------
class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class TierStatus(str, Enum):
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"
    TIMEOUT = "timeout"


class DomainStatus(str, Enum):
    OK = "OK"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class CleanStatus(str, Enum):
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"


# ---------- Tier 1 Models ----------
class Tier1Result(BaseModel):
    """Tier 1: Client‑side pre‑validation results from the Chrome extension."""

    score: int = Field(..., ge=0, le=100, description="Heuristic score (0‑100)")
    evidence: List[str] = Field(default_factory=list, description="Evidence strings from heuristics")
    status: CleanStatus = Field(..., description="Clean or Suspicious based on heuristics")
    execution_time_ms: Optional[float] = Field(None, ge=0, description="Execution time in milliseconds")

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, v: List[str]) -> List[str]:
        if v is None:
            return []
        return [e.strip() for e in v if e and e.strip()]


# ---------- Tier 2 Models ----------
class DomainAnalysis(BaseModel):
    """Domain metadata analysis (WHOIS, reputation, etc.)."""

    status: DomainStatus = Field(..., description="Status of the domain")
    score: float = Field(..., ge=0.0, le=100.0, description="Domain risk score")
    weight: float = Field(default=0.3, ge=0.0, le=1.0, description="Weight in fusion")


class ThreatAnalysisDetail(BaseModel):
    """Detailed threat pattern analysis (lexical, keyword, etc.)."""

    threat_level: int = Field(..., ge=0, le=100, description="Threat level (0‑100)")
    category: str = Field(..., min_length=1, description="Category of threat")
    reasoning: str = Field(..., min_length=1, description="Explanation of the analysis")
    flagged_phrases: List[str] = Field(default_factory=list, description="Phrases that triggered flags")


class Tier2Analysis(BaseModel):
    """Tier 2 threat analysis summary."""

    status: DomainStatus = Field(..., description="Overall Tier 2 status")
    score: float = Field(..., ge=0.0, le=100.0, description="Tier 2 score")
    weight: float = Field(default=0.7, ge=0.0, le=1.0, description="Weight in fusion")


class Tier2Result(BaseModel):
    """Tier 2: Metadata and pattern analysis results."""

    score: float = Field(..., ge=0.0, le=100.0, description="Weighted combination of domain + threat")
    domain_analysis: DomainAnalysis
    threat_analysis: Tier2Analysis
    threat_details: ThreatAnalysisDetail
    evidence: List[str] = Field(default_factory=list, description="Evidence from Tier 2")
    execution_time_ms: Optional[float] = Field(None, ge=0, description="Execution time in milliseconds")


# ---------- Tier 3 Models ----------
class Tier3Result(BaseModel):
    """Tier 3: AI semantic analysis results (Gemini)."""

    score: int = Field(..., ge=0, le=100, description="AI score (0‑100)")
    category: str = Field(..., min_length=1, description="Category from AI (e.g., BEC, Credential)")
    reasoning: str = Field(..., min_length=1, description="AI explanation")
    flagged_phrases: List[str] = Field(default_factory=list, description="Phrases flagged by AI")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="AI confidence")
    execution_time_ms: Optional[float] = Field(None, ge=0, description="Execution time in milliseconds")
    status: TierStatus = Field(default=TierStatus.COMPLETE, description="Status of AI processing")


# ---------- Gateway Request ----------
class GatewayScanRequest(BaseModel):
    """Request to gateway with Tier 1 results and email data."""

    # Tier 1 data
    tier1_score: int = Field(..., ge=0, le=100, description="Tier 1 heuristic score")
    tier1_evidence: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="Evidence from client‑side analysis",
    )

    # Email data
    sender: EmailStr = Field(..., description="Email sender address")
    body: str = Field(..., max_length=50000, description="Email body text (max 50KB)")
    links: List[str] = Field(..., max_length=100, description="URLs found in email")

    # Optional metadata
    subject: Optional[str] = Field(None, max_length=500, description="Email subject line")
    timestamp: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Request timestamp (UTC)",
    )

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Body cannot be empty")
        return v.strip()

    @field_validator("links")
    @classmethod
    def validate_links(cls, v: List[str]) -> List[str]:
        if v is None:
            return []
        return [link.strip() for link in v if isinstance(link, str) and link.strip()]


# ---------- Scoring Weights ----------
class ScoringWeights(BaseModel):
    """Scoring weights for each tier (must sum to 1.0)."""

    tier1: float = Field(default=0.2, ge=0.0, le=1.0)
    tier2: float = Field(default=0.3, ge=0.0, le=1.0)
    tier3: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("tier1", "tier2", "tier3")
    @classmethod
    def validate_weights(cls, v: float) -> float:
        return round(v, 4)

    def model_post_init(self, __context: Any) -> None:
        total = self.tier1 + self.tier2 + self.tier3
        if not (0.999 <= total <= 1.001):
            raise ValueError(f"Weights must sum to 1.0 (got {total})")


# ---------- Gateway Response ----------
class GatewayScanResponse(BaseModel):
    """Gateway response with all tier results."""

    # Scan metadata
    scan_id: str = Field(..., min_length=1, description="Unique scan identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Response timestamp (UTC)",
    )

    # Scoring
    partial_score: float = Field(..., ge=0.0, le=100.0, description="T1 + T2 score (60% of final)")
    final_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Full score (100%)")
    verdict: Verdict = Field(..., description="Final verdict")

    # Tier results
    tier1: Tier1Result
    tier2: Tier2Result
    tier3: Optional[Tier3Result] = None

    # Status
    tier3_status: TierStatus = Field(default=TierStatus.PROCESSING)
    complete: bool = False
    layers_completed: int = Field(default=0, ge=0, le=3, description="Number of tiers completed")

    # Evidence and metadata
    combined_evidence: List[str] = Field(default_factory=list, description="Aggregated evidence")
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    cached: bool = False
    sender: Optional[EmailStr] = None
    subject: Optional[str] = Field(None, max_length=500)

    # Performance
    total_execution_time_ms: Optional[float] = Field(None, ge=0, description="Total processing time")

    @field_validator("combined_evidence")
    @classmethod
    def validate_evidence(cls, v: List[str]) -> List[str]:
        if v is None:
            return []
        return [e for e in v if e and e.strip()]


# ---------- Scan Status Polling ----------
class ScanStatusResponse(BaseModel):
    """Response for polling scan status (e.g., when Tier 3 is still processing)."""

    scan_id: str = Field(..., min_length=1)
    complete: bool
    layers_completed: int = Field(default=0, ge=0, le=3)
    tier3_status: TierStatus
    final_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    verdict: Verdict
    tier3: Optional[Tier3Result] = None
    estimated_completion_ms: Optional[int] = Field(None, ge=0, description="Estimated remaining time")


# ---------- Error Models ----------
class TierError(BaseModel):
    """Error information for a failed tier."""

    tier: str = Field(..., description="Failed tier (tier1, tier2, tier3)")
    error_type: str = Field(..., min_length=1, description="Error type/code")
    message: str = Field(..., min_length=1, description="Human‑readable error")
    fallback_score: int = Field(default=50, ge=0, le=100, description="Default score used on failure")