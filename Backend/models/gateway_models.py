"""
Shared data models for ZeroPhish Gateway
"""
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

# ============================================================================
# TIER 1 MODELS (Client-Side)
# ============================================================================

class Tier1Result(BaseModel):
    """Tier 1: Client-side pre-validation results"""
    score: int  # 0-100
    evidence: List[str]
    status: str  # "Clean" | "Suspicious"
    execution_time_ms: Optional[float] = None


# ============================================================================
# TIER 2 MODELS (Metadata Layer)
# ============================================================================

class DomainAnalysis(BaseModel):
    """Domain metadata analysis"""
    status: str  # "OK" | "SUSPICIOUS" | "CRITICAL" | "UNKNOWN" | "ERROR"
    score: float
    weight: float = 0.3


class ThreatAnalysisDetail(BaseModel):
    """Detailed threat pattern analysis"""
    threat_level: int  # 0-100
    category: str
    reasoning: str
    flagged_phrases: List[str]


class Tier2Analysis(BaseModel):
    """Tier 2 threat analysis results"""
    status: str  # "OK" | "SUSPICIOUS" | "CRITICAL"
    score: float
    weight: float = 0.7


class Tier2Result(BaseModel):
    """Tier 2: Metadata and pattern analysis results"""
    score: float  # 0-100 (weighted combination of domain + threat)
    domain_analysis: DomainAnalysis
    threat_analysis: Tier2Analysis
    threat_details: ThreatAnalysisDetail
    evidence: List[str]
    execution_time_ms: Optional[float] = None


# ============================================================================
# TIER 3 MODELS (AI Analysis)
# ============================================================================

class Tier3Result(BaseModel):
    """Tier 3: AI semantic analysis results"""
    score: int  # 0-100
    category: str
    reasoning: str
    flagged_phrases: List[str]
    confidence: Optional[float] = None
    execution_time_ms: Optional[float] = None
    status: str = "complete"  # "processing" | "complete" | "failed" | "timeout"


# ============================================================================
# GATEWAY MODELS
# ============================================================================

class GatewayScanRequest(BaseModel):
    """Request to gateway with Tier 1 results and email data"""
    # Tier 1 data from extension
    tier1_score: int  # 0-100
    tier1_evidence: List[str]
    
    # Email data for Tier 2 and Tier 3
    sender: str
    body: str
    links: List[str]
    
    # Optional metadata
    subject: Optional[str] = None
    timestamp: Optional[str] = None


class ScoringWeights(BaseModel):
    """Scoring weights for each tier"""
    tier1: float = 0.2
    tier2: float = 0.3
    tier3: float = 0.5


class GatewayScanResponse(BaseModel):
    """Gateway response with all tier results"""
    # Scan metadata
    scan_id: str
    timestamp: str
    
    # Scoring
    partial_score: float  # T1 + T2 only (60% of final)
    final_score: Optional[float] = None  # All tiers (100%)
    verdict: str  # "SAFE" | "SUSPICIOUS" | "CRITICAL"
    
    # Tier results
    tier1: Tier1Result
    tier2: Tier2Result
    tier3: Optional[Tier3Result] = None
    
    # Status
    tier3_status: str = "processing"  # "processing" | "complete" | "failed" | "timeout"
    complete: bool = False
    
    # Evidence and metadata
    combined_evidence: List[str]
    weights: ScoringWeights
    cached: bool = False
    
    # Performance
    total_execution_time_ms: Optional[float] = None


class ScanStatusResponse(BaseModel):
    """Response for polling scan status"""
    scan_id: str
    complete: bool
    tier3_status: str
    final_score: Optional[float] = None
    verdict: str
    tier3: Optional[Tier3Result] = None
    estimated_completion_ms: Optional[int] = None


# ============================================================================
# ERROR MODELS
# ============================================================================

class TierError(BaseModel):
    """Error information for a failed tier"""
    tier: str  # "tier1" | "tier2" | "tier3"
    error_type: str
    message: str
    fallback_score: int = 50  # Default score when tier fails
