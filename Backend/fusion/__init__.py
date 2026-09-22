"""
ZeroPhish Detection Fusion Package
==================================
Canonical multi-tier detection fusion, evidence normalization,
source authority, and explainability engine.
"""

from .models import (
    AuthorityLevel,
    CanonicalEvidence,
    EvidenceSeverity,
    EvidenceSource,
    FusionExplanation,
    FusionResult,
    TierExecutionSummary,
)
from .normalizer import EvidenceNormalizer
from .engine import (
    FusionEngine,
    fuse_detection_results,
    calculate_partial_score,
    calculate_fused_score,
    determine_canonical_verdict,
)

__all__ = [
    "AuthorityLevel",
    "CanonicalEvidence",
    "EvidenceSeverity",
    "EvidenceSource",
    "FusionExplanation",
    "FusionResult",
    "TierExecutionSummary",
    "EvidenceNormalizer",
    "FusionEngine",
    "fuse_detection_results",
    "calculate_partial_score",
    "calculate_fused_score",
    "determine_canonical_verdict",
]
