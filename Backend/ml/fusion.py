"""
Multi‑Signal Risk Fusion Engine for ZeroPhish.

Combines heuristics, OSINT, ML inferences, and Tier 3 AI with hard security rule overrides.
Supports custom weights and partial fusions (T1+T2, T1+T2+T3).
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class FusionSignal(BaseModel):
    name: str
    score: float  # 0 to 100
    weight: float
    confidence: float = 1.0
    evidence: Optional[str] = None


class FusionResult(BaseModel):
    final_score: float = Field(..., ge=0.0, le=100.0)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    signals_applied: List[str]
    hard_override_applied: Optional[str] = None
    breakdown: Dict[str, float]


class RiskFusionEngine:
    """Calibrated Multi‑Signal Fusion with Hard Security Overrides."""

    # Default weights matching production formula (T1 20%, T2 30%, T3 50%)
    DEFAULT_WEIGHTS = {
        "tier1_heuristics": 0.20,
        "tier2_metadata_ml": 0.30,
        "tier3_semantic_ai": 0.50,
    }
    SAFE_THRESHOLD = 30.0
    CRITICAL_THRESHOLD = 70.0
    HARD_MALICIOUS_SCORE = 95.0
    HARD_SAFE_SCORE = 5.0

    @staticmethod
    def clamp(val: float) -> float:
        """Clamp value to [0.0, 100.0]."""
        return max(0.0, min(100.0, float(val)))

    @classmethod
    def fuse(
        cls,
        tier1_score: float,
        tier2_score: float,
        tier3_score: Optional[float] = None,
        hard_malicious_triggers: Optional[List[str]] = None,
        hard_safe_triggers: Optional[List[str]] = None,
        custom_weights: Optional[Dict[str, float]] = None,
    ) -> FusionResult:
        """
        Execute risk fusion with hard security overrides.

        Args:
            tier1_score: Heuristics score (0‑100).
            tier2_score: Metadata/ML score (0‑100).
            tier3_score: Semantic AI score (0‑100) – optional.
            hard_malicious_triggers: List of triggers that force CRITICAL.
            hard_safe_triggers: List of triggers that force SAFE (overridden by malicious).
            custom_weights: Override default weights (must include all three keys if tier3 provided).

        Returns:
            FusionResult with final score, verdict, and breakdown.
        """
        weights = custom_weights or cls.DEFAULT_WEIGHTS

        # 1. Hard overrides take precedence
        if hard_malicious_triggers:
            return FusionResult(
                final_score=cls.HARD_MALICIOUS_SCORE,
                verdict=Verdict.CRITICAL,
                confidence=0.99,
                signals_applied=hard_malicious_triggers,
                hard_override_applied=f"Hard security trigger: {', '.join(hard_malicious_triggers)}",
                breakdown={"hard_override": cls.HARD_MALICIOUS_SCORE},
            )

        if hard_safe_triggers:
            return FusionResult(
                final_score=cls.HARD_SAFE_SCORE,
                verdict=Verdict.SAFE,
                confidence=0.95,
                signals_applied=hard_safe_triggers,
                hard_override_applied=f"Verified safe allowlist: {', '.join(hard_safe_triggers)}",
                breakdown={"hard_override": cls.HARD_SAFE_SCORE},
            )

        # 2. Clamp inputs
        t1 = cls.clamp(tier1_score)
        t2 = cls.clamp(tier2_score)
        breakdown = {"tier1": t1, "tier2": t2}
        signals = [f"Tier 1 Heuristics: {t1:.1f}", f"Tier 2 Metadata/ML: {t2:.1f}"]

        # 3. Weighted fusion
        if tier3_score is not None:
            t3 = cls.clamp(tier3_score)
            breakdown["tier3"] = t3
            signals.append(f"Tier 3 Semantic AI: {t3:.1f}")
            w1 = weights.get("tier1_heuristics", 0.20)
            w2 = weights.get("tier2_metadata_ml", 0.30)
            w3 = weights.get("tier3_semantic_ai", 0.50)
            total_w = w1 + w2 + w3
            raw_score = (t1 * w1 + t2 * w2 + t3 * w3) / total_w
            confidence = 0.92
        else:
            # Partial fusion (T1 + T2)
            w1 = weights.get("tier1_heuristics", 0.20)
            w2 = weights.get("tier2_metadata_ml", 0.30)
            total_w = w1 + w2
            raw_score = (t1 * w1 + t2 * w2) / total_w
            confidence = 0.75

        final_score = round(cls.clamp(raw_score), 2)

        # 4. Verdict categorisation
        if final_score < cls.SAFE_THRESHOLD:
            verdict = Verdict.SAFE
        elif final_score < cls.CRITICAL_THRESHOLD:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CRITICAL

        return FusionResult(
            final_score=final_score,
            verdict=verdict,
            confidence=confidence,
            signals_applied=signals,
            hard_override_applied=None,
            breakdown=breakdown,
        )