"""
Multi-Signal Risk Fusion Engine for ZeroPhish.
Combines heuristics, OSINT, ML inferences, and Tier 3 AI with hard security rule overrides.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class FusionSignal(BaseModel):
    name: str
    score: float  # 0 to 100
    weight: float
    confidence: float = 1.0
    evidence: Optional[str] = None


class FusionResult(BaseModel):
    final_score: float = Field(..., ge=0.0, le=100.0)
    verdict: str  # "SAFE" | "SUSPICIOUS" | "CRITICAL"
    confidence: float = Field(..., ge=0.0, le=1.0)
    signals_applied: List[str]
    hard_override_applied: Optional[str] = None
    breakdown: Dict[str, float]


class RiskFusionEngine:
    """Calibrated Multi-Signal Fusion with Hard Security Overrides."""

    # Default weights matching production formula
    DEFAULT_WEIGHTS = {
        "tier1_heuristics": 0.20,
        "tier2_metadata_ml": 0.30,
        "tier3_semantic_ai": 0.50,
    }

    @staticmethod
    def clamp(val: float) -> float:
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
        """
        weights = custom_weights or cls.DEFAULT_WEIGHTS
        signals: List[str] = []
        breakdown: Dict[str, float] = {}

        # 1. Evaluate Hard Security Rule Overrides
        if hard_malicious_triggers:
            override_reason = f"Hard security trigger: {', '.join(hard_malicious_triggers)}"
            return FusionResult(
                final_score=95.0,
                verdict="CRITICAL",
                confidence=0.99,
                signals_applied=hard_malicious_triggers,
                hard_override_applied=override_reason,
                breakdown={"hard_override": 95.0},
            )

        if hard_safe_triggers and not hard_malicious_triggers:
            override_reason = f"Verified safe allowlist: {', '.join(hard_safe_triggers)}"
            return FusionResult(
                final_score=5.0,
                verdict="SAFE",
                confidence=0.95,
                signals_applied=hard_safe_triggers,
                hard_override_applied=override_reason,
                breakdown={"hard_override": 5.0},
            )

        # 2. Weighted Score Fusion
        t1 = cls.clamp(tier1_score)
        t2 = cls.clamp(tier2_score)
        breakdown["tier1"] = t1
        breakdown["tier2"] = t2
        signals.append(f"Tier 1 Heuristics: {t1:.1f}")
        signals.append(f"Tier 2 Metadata/ML: {t2:.1f}")

        if tier3_score is not None:
            t3 = cls.clamp(tier3_score)
            breakdown["tier3"] = t3
            signals.append(f"Tier 3 Semantic AI: {t3:.1f}")
            w_t1 = weights.get("tier1_heuristics", 0.20)
            w_t2 = weights.get("tier2_metadata_ml", 0.30)
            w_t3 = weights.get("tier3_semantic_ai", 0.50)
            total_w = w_t1 + w_t2 + w_t3
            raw_score = (t1 * w_t1 + t2 * w_t2 + t3 * w_t3) / total_w
            confidence = 0.92
        else:
            # Partial fusion (T1 + T2)
            w_t1 = weights.get("tier1_heuristics", 0.20)
            w_t2 = weights.get("tier2_metadata_ml", 0.30)
            total_w = w_t1 + w_t2
            raw_score = (t1 * w_t1 + t2 * w_t2) / total_w
            confidence = 0.75

        final_score = round(cls.clamp(raw_score), 2)

        # 3. Verdict Categorization
        if final_score < 30.0:
            verdict = "SAFE"
        elif final_score < 70.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CRITICAL"

        return FusionResult(
            final_score=final_score,
            verdict=verdict,
            confidence=confidence,
            signals_applied=signals,
            hard_override_applied=None,
            breakdown=breakdown,
        )
