"""
Detection Fusion Engine
=======================
Single authoritative detection-fusion engine for ZeroPhish.
Combines Tier 1, Tier 2, Tier 3, and Vision into deterministic,
monotonic, explainable security verdicts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CanonicalEvidence,
    EvidenceSeverity,
    EvidenceSource,
    FusionExplanation,
    FusionResult,
    TierExecutionSummary,
)
from .normalizer import EvidenceNormalizer

logger = logging.getLogger(__name__)

# Canonical Verdict Thresholds
THRESHOLD_SAFE = 30.0
THRESHOLD_SUSPICIOUS = 70.0


def determine_canonical_verdict(
    score: Optional[float],
    is_degraded: bool = False,
    deterministic_evaluated: bool = True,
) -> str:
    """
    Map risk score (0-100) to canonical verdict string.

    SAFE: Score < 30.0 AND deterministic evaluation completed cleanly.
    SUSPICIOUS: 30.0 <= Score < 70.0 (or fail-safe degraded state).
    CRITICAL: Score >= 70.0.
    UNKNOWN: Deterministic evaluation could not run or returned no valid data.
    """
    if score is None or not deterministic_evaluated:
        return "UNKNOWN"

    clamped = max(0.0, min(100.0, float(score)))

    if clamped >= THRESHOLD_SUSPICIOUS:
        return "CRITICAL"
    elif clamped >= THRESHOLD_SAFE:
        return "SUSPICIOUS"
    else:
        # If degraded due to internal errors, fail safe to SUSPICIOUS, never false SAFE
        if is_degraded:
            return "SUSPICIOUS"
        return "SAFE"



def calculate_partial_score(
    tier1_score: Optional[float],
    tier2_score: Optional[float],
) -> Optional[float]:
    """
    Calculate authoritative server partial score from Tier 1 (40%) and Tier 2 (60%).
    Reflects the 0.20 : 0.30 ratio of Tier 1 to Tier 2 in standard config.
    If one tier is unavailable, the available server-authoritative tier provides 100% of the baseline.
    If neither tier is available, returns None (insufficient evidence; cannot evaluate).
    """
    if tier1_score is not None and tier2_score is not None:
        t1 = max(0.0, min(100.0, float(tier1_score)))
        t2 = max(0.0, min(100.0, float(tier2_score)))
        return round((t1 * 0.40) + (t2 * 0.60), 2)
    elif tier1_score is not None:
        return round(max(0.0, min(100.0, float(tier1_score))), 2)
    elif tier2_score is not None:
        return round(max(0.0, min(100.0, float(tier2_score))), 2)
    else:
        return None


# Base reference weights across tiers
BASE_WEIGHTS = {
    "tier1": 0.15,
    "tier2": 0.25,
    "tier3": 0.45,
    "vision": 0.15,
}

# Standard established weight profiles for canonical combinations
ESTABLISHED_PROFILES = {
    ("tier1", "tier2", "tier3", "vision"): {"tier1": 0.15, "tier2": 0.25, "tier3": 0.45, "vision": 0.15},
    ("tier1", "tier2", "tier3"): {"tier1": 0.20, "tier2": 0.30, "tier3": 0.50},
    ("tier1", "tier2", "vision"): {"tier1": 0.25, "tier2": 0.50, "vision": 0.25},
    ("tier1", "tier2"): {"tier1": 0.40, "tier2": 0.60},
}


def calculate_fused_score(
    tier1_score: Optional[float] = None,
    tier2_score: Optional[float] = None,
    tier3_score: Optional[float] = None,
    vision_score: Optional[float] = None,
) -> Tuple[Optional[float], Dict[str, float]]:
    """
    Calculate multi-tier fused score dynamically based on which tiers participated.
    Returns (fused_score, dict_of_applied_weights).

    If a tier is failed / unconfigured (score is None), it is excluded from participation.
    Active tiers have their weights renormalized proportionally such that sum(weights) == 1.0.
    If no tiers participated, returns (None, {}).
    """
    scores: Dict[str, float] = {}
    if tier1_score is not None:
        scores["tier1"] = max(0.0, min(100.0, float(tier1_score)))
    if tier2_score is not None:
        scores["tier2"] = max(0.0, min(100.0, float(tier2_score)))
    if tier3_score is not None:
        scores["tier3"] = max(0.0, min(100.0, float(tier3_score)))
    if vision_score is not None:
        scores["vision"] = max(0.0, min(100.0, float(vision_score)))

    if not scores:
        return None, {}

    # 1. Match against established canonical profiles if applicable
    matched_weights = None
    for profile_keys, p_weights in ESTABLISHED_PROFILES.items():
        if set(profile_keys) == set(scores.keys()):
            matched_weights = dict(p_weights)
            break

    if matched_weights is not None:
        weights = matched_weights
    else:
        # 2. General proportional renormalization policy
        total_base = sum(BASE_WEIGHTS[k] for k in scores.keys())
        raw_weights = {k: BASE_WEIGHTS[k] / total_base for k in scores.keys()}
        rounded_weights = {k: round(v, 4) for k, v in raw_weights.items()}
        diff = round(1.0 - sum(rounded_weights.values()), 4)
        max_k = max(rounded_weights.keys(), key=lambda k: rounded_weights[k])
        rounded_weights[max_k] = round(rounded_weights[max_k] + diff, 4)
        weights = rounded_weights

    fused_score = sum(scores[k] * weights[k] for k in scores.keys())
    return round(fused_score, 2), weights


class FusionEngine:
    """
    Core authoritative security decision engine.
    """

    @classmethod
    def fuse(
        cls,
        tier1_result: Any,
        tier2_result: Any,
        tier3_result: Optional[Any] = None,
        vision_result: Optional[Any] = None,
        established_partial_score: Optional[float] = None,
        established_verdict: Optional[str] = None,
    ) -> FusionResult:
        """
        Execute full multi-tier fusion pipeline.
        """
        # 1. Inspect Tier 1 Status & Score (Server-Authoritative)
        t1_score: Optional[float] = None
        t1_participated = False
        t1_degraded = False
        t1_status_str = "failed"
        t1_reason: Optional[str] = None

        if tier1_result is not None:
            raw_t1_status = getattr(tier1_result, "status", None)
            st_val = (raw_t1_status.value if hasattr(raw_t1_status, "value") else str(raw_t1_status or "")).lower()
            raw_t1_score = getattr(tier1_result, "score", None)

            if st_val in ("failed", "error"):
                t1_status_str = "failed"
                t1_reason = "Tier 1 heuristic execution failed."
            elif raw_t1_score is not None:
                t1_score = float(raw_t1_score)
                t1_participated = True
                t1_degraded = getattr(tier1_result, "source", "") == "degraded" or getattr(tier1_result, "degraded", False)
                t1_status_str = "degraded" if t1_degraded else "complete"
            else:
                t1_status_str = "failed"
                t1_reason = "Tier 1 heuristic score missing."
        else:
            t1_status_str = "failed"
            t1_reason = "Tier 1 result not provided."

        # 2. Inspect Tier 2 Status & Score (Server-Authoritative)
        t2_score: Optional[float] = None
        t2_participated = False
        t2_degraded = False
        t2_status_str = "failed"
        t2_reason: Optional[str] = None

        if tier2_result is not None:
            raw_t2_status = getattr(tier2_result, "status", None)
            st_val = (raw_t2_status.value if hasattr(raw_t2_status, "value") else str(raw_t2_status or "")).lower()
            raw_t2_score = getattr(tier2_result, "score", None)

            if st_val in ("failed", "error"):
                t2_status_str = "failed"
                t2_reason = "Tier 2 analysis execution failed."
            elif raw_t2_score is not None:
                t2_score = float(raw_t2_score)
                t2_participated = True
                if getattr(tier2_result, "domain_analysis", None):
                    d_status = getattr(tier2_result.domain_analysis, "status", None)
                    d_val = (d_status.value if hasattr(d_status, "value") else str(d_status or "")).upper()
                    if d_val in ("ERROR", "LOOKUP_FAILED"):
                        t2_degraded = True
                        t2_status_str = "degraded"
                        t2_reason = "Domain intelligence lookup timed out or failed."
                    else:
                        t2_status_str = "complete"
                else:
                    t2_status_str = "complete"
            else:
                t2_status_str = "failed"
                t2_reason = "Tier 2 analysis score missing."
        else:
            t2_status_str = "failed"
            t2_reason = "Tier 2 result not provided."

        # 3. Calculate Deterministic Server Partial Score & Verdict
        calculated_partial = calculate_partial_score(t1_score, t2_score)
        deterministic_evaluated = (t1_participated or t2_participated) and not (t1_degraded and t2_degraded)

        # Determine partial verdict & floor
        if calculated_partial is not None:
            active_authoritative_scores = [s for s in (t1_score, t2_score) if s is not None]
            deterministic_max = max(active_authoritative_scores) if active_authoritative_scores else calculated_partial

            if deterministic_max >= THRESHOLD_SUSPICIOUS:
                partial_verdict = "CRITICAL"
                partial_score = max(calculated_partial, deterministic_max)
            elif deterministic_max >= THRESHOLD_SAFE:
                partial_verdict = "SUSPICIOUS"
                partial_score = max(calculated_partial, deterministic_max)
            else:
                partial_score = calculated_partial
                partial_verdict = determine_canonical_verdict(
                    partial_score,
                    is_degraded=(t1_degraded or t2_degraded or not t1_participated or not t2_participated),
                    deterministic_evaluated=deterministic_evaluated,
                )
        else:
            # Neither server-authoritative tier participated!
            partial_score = None
            partial_verdict = "UNKNOWN"

        # If an established partial score/verdict from earlier stage was provided, enforce monotonicity
        if established_partial_score is not None:
            if partial_score is not None:
                partial_score = max(partial_score, float(established_partial_score))
            else:
                partial_score = float(established_partial_score)
        if established_verdict is not None:
            est_v = established_verdict.value if hasattr(established_verdict, "value") else str(established_verdict)
            if est_v == "CRITICAL" or partial_verdict == "CRITICAL":
                partial_verdict = "CRITICAL"
            elif est_v == "SUSPICIOUS" and partial_verdict != "CRITICAL":
                partial_verdict = "SUSPICIOUS"

        # 4. Inspect Tier 3 Advisory Participation
        t3_score: Optional[float] = None
        t3_status = "not_requested"
        t3_reason: Optional[str] = None

        if tier3_result:
            raw_t3_status = getattr(tier3_result, "status", None)
            status_val = (raw_t3_status.value if hasattr(raw_t3_status, "value") else str(raw_t3_status)).lower()
            category = str(getattr(tier3_result, "category", "")).upper()

            if status_val in ("complete", "success") and not category.startswith("AI_"):
                t3_score = float(getattr(tier3_result, "score", 0))
                t3_status = "complete"
            elif status_val == "timeout" or "TIMEOUT" in category:
                t3_status = "timeout"
                t3_reason = "Tier 3 AI inference timed out."
            else:
                t3_status = "failed"
                t3_reason = f"Tier 3 AI execution failed: {category or status_val}."

        # 5. Inspect Vision Advisory Participation
        v_score: Optional[float] = None
        v_status = "not_requested"
        v_reason: Optional[str] = None
        v_requires_followup = False

        if vision_result:
            raw_v_status = getattr(vision_result, "status", None)
            v_status_val = (raw_v_status.value if hasattr(raw_v_status, "value") else str(raw_v_status)).lower()
            v_requires_followup = bool(getattr(vision_result, "requires_followup", False))

            if v_status_val in ("complete", "success", "implemented") and getattr(vision_result, "visual_score", None) is not None:
                v_score = float(vision_result.visual_score)
                v_status = "complete"
            elif v_status_val == "timeout":
                v_status = "timeout"
                v_reason = "Vision screenshot analysis timed out."
            elif v_status_val == "visual_required":
                v_status = "visual_required"
                v_reason = "Visual verification required by AI, but screenshot was not provided."
                v_requires_followup = True
            elif v_status_val in ("failed", "invalid_image", "invalid_payload", "bomb_detected"):
                v_status = "failed"
                v_reason = f"Vision validation rejected image ({v_status_val})."
            else:
                v_status = v_status_val
                v_reason = "Vision analysis not available."
        elif tier3_result and getattr(tier3_result, "requires_visual_check", False):
            # Vision was required by Tier 3, but screenshot was missing/not provided
            # Must report visual_required, NEVER not_requested
            v_status = "visual_required"
            v_reason = "Visual verification required by AI, but screenshot was not provided."
            v_requires_followup = True


        # 6. Calculate Weighted Multi-Tier Score
        raw_fused, weights = calculate_fused_score(
            tier1_score=t1_score,
            tier2_score=t2_score,
            tier3_score=t3_score,
            vision_score=v_score,
        )

        # 7. Apply Security Monotonicity Invariants (Phase 1.5A, 1.6, 1.7)
        # Advisory layers (T3, Vision) cannot downgrade deterministic findings.
        final_score: Optional[float] = raw_fused

        # Invariant A: If partial verdict is CRITICAL, final score and verdict must remain CRITICAL
        if partial_verdict == "CRITICAL" or (partial_score is not None and partial_score >= THRESHOLD_SUSPICIOUS):
            base_cand = [c for c in (raw_fused, partial_score, THRESHOLD_SUSPICIOUS) if c is not None]
            final_score = max(base_cand) if base_cand else THRESHOLD_SUSPICIOUS
        # Invariant B: If partial verdict is SUSPICIOUS, final score cannot drop below partial score or THRESHOLD_SAFE
        elif partial_verdict == "SUSPICIOUS" or (partial_score is not None and partial_score >= THRESHOLD_SAFE):
            base_cand = [c for c in (raw_fused, partial_score, THRESHOLD_SAFE) if c is not None]
            final_score = max(base_cand) if base_cand else THRESHOLD_SAFE
        # Invariant C: If advisory scores failed/timed out, final score strictly equals partial score
        elif t3_score is None and v_score is None:
            final_score = partial_score
        else:
            final_score = raw_fused

        # Round final score if present
        if final_score is not None:
            final_score = round(max(0.0, min(100.0, final_score)), 2)

        # 8. Determine Final Canonical Verdict
        authoritative_degraded = (
            t1_degraded or t2_degraded or not t1_participated or not t2_participated
        )
        is_any_degraded = (
            authoritative_degraded or (t3_status in ("failed", "timeout")) or (v_status in ("failed", "timeout"))
        )
        final_verdict = determine_canonical_verdict(
            final_score,
            is_degraded=authoritative_degraded,
            deterministic_evaluated=deterministic_evaluated,
        )

        # Enforce Monotonicity on Final Verdict
        if partial_verdict == "CRITICAL":
            final_verdict = "CRITICAL"
        elif partial_verdict == "SUSPICIOUS" and final_verdict == "SAFE":
            final_verdict = "SUSPICIOUS"
        elif partial_verdict == "UNKNOWN" and not deterministic_evaluated:
            # If deterministic tiers did not run, advisory tiers cannot declare SAFE.
            if final_score is not None and final_score >= THRESHOLD_SUSPICIOUS:
                final_verdict = "CRITICAL"
            elif final_score is not None and final_score >= THRESHOLD_SAFE:
                final_verdict = "SUSPICIOUS"
            else:
                final_verdict = "UNKNOWN"

        # 9. Evidence Normalization & Deduplication
        norm_t1 = EvidenceNormalizer.normalize_tier1(
            evidence_list=getattr(tier1_result, "evidence", []) if tier1_result else [],
            source_label=getattr(tier1_result, "source", "server_verified") if tier1_result else "server_verified",
            server_score=getattr(tier1_result, "server_score", None) if tier1_result else None,
        )
        d_analysis = getattr(tier2_result, "domain_analysis", None) if tier2_result else None
        d_status_obj = getattr(d_analysis, "status", None)
        d_status_str = d_status_obj.value if hasattr(d_status_obj, "value") else str(d_status_obj or "UNKNOWN")

        norm_t2 = EvidenceNormalizer.normalize_tier2(
            evidence_list=getattr(tier2_result, "evidence", []) if tier2_result else [],
            domain_age_days=getattr(d_analysis, "score", None),
            domain_status=d_status_str if tier2_result else None,
            category=getattr(getattr(tier2_result, "threat_details", None), "category", None) if tier2_result else None,
            flagged_phrases=getattr(getattr(tier2_result, "threat_details", None), "flagged_phrases", []) if tier2_result else [],
        )
        norm_t3 = EvidenceNormalizer.normalize_tier3(tier3_result)
        norm_v = EvidenceNormalizer.normalize_vision(vision_result)

        all_evidence = norm_t1 + norm_t2 + norm_t3 + norm_v
        canonical_ev, string_ev = EvidenceNormalizer.deduplicate_and_merge(all_evidence)

        # 10. Construct Explainability Model
        top_reasons: List[str] = []
        if final_verdict == "SAFE":
            top_reasons.append("No material phishing indicators identified across active detection layers.")
        elif final_verdict == "UNKNOWN":
            top_reasons.append("Insufficient evidence: Authoritative detection tiers unavailable to evaluate threat.")
        else:
            for ev in canonical_ev:
                if ev.severity in (EvidenceSeverity.CRITICAL, EvidenceSeverity.HIGH):
                    top_reasons.append(ev.description)
                if len(top_reasons) >= 4:
                    break
            if not top_reasons:
                for ev in canonical_ev:
                    if ev.severity == EvidenceSeverity.MEDIUM:
                        top_reasons.append(ev.description)
                    if len(top_reasons) >= 3:
                        break
            if not top_reasons:
                top_reasons.append("Risk indicators insufficient for conclusive threat classification.")

        limitations: List[str] = []
        if not t1_participated:
            limitations.append(f"Tier 1: {t1_reason or 'Did not participate.'}")
        elif t1_degraded:
            limitations.append("Tier 1 heuristics degraded due to internal evaluation exception.")
        if not t2_participated:
            limitations.append(f"Tier 2: {t2_reason or 'Did not participate.'}")
        elif t2_degraded:
            limitations.append("Tier 2 intelligence lookup failed or was incomplete.")
        if t3_reason:
            limitations.append(f"Tier 3 AI: {t3_reason}")
        if v_reason:
            limitations.append(f"Vision: {v_reason}")

        tier_summaries = {
            "tier1": TierExecutionSummary(
                tier="tier1",
                status=t1_status_str,
                score=t1_score,
                weight=weights.get("tier1", 0.0),
                authoritative=True,
                participated=t1_participated,
                reason=t1_reason,
            ),
            "tier2": TierExecutionSummary(
                tier="tier2",
                status=t2_status_str,
                score=t2_score,
                weight=weights.get("tier2", 0.0),
                authoritative=True,
                participated=t2_participated,
                reason=t2_reason or ("Domain lookup incomplete" if t2_degraded else None),
            ),
            "tier3": TierExecutionSummary(
                tier="tier3",
                status=t3_status,
                score=t3_score,
                weight=weights.get("tier3", 0.0),
                authoritative=False,
                participated=(t3_score is not None),
                reason=t3_reason,
            ),
            "vision": TierExecutionSummary(
                tier="vision",
                status=str(v_status).lower(),
                score=v_score,
                weight=weights.get("vision", 0.0),
                authoritative=False,
                participated=(v_score is not None),
                reason=v_reason,
                requires_followup=v_requires_followup,
            ),

        }

        # Calculate evidence certainty / coverage confidence
        active_weights_sum = sum(s.weight for s in tier_summaries.values() if s.participated)
        coverage_confidence = round(min(1.0, max(0.0, active_weights_sum)), 2)

        explanation = FusionExplanation(
            verdict=final_verdict,
            final_score=final_score,
            top_reasons=top_reasons,
            contributing_evidence=canonical_ev[:10],
            tier_summaries=tier_summaries,
            limitations=limitations,
        )

        return FusionResult(
            partial_score=partial_score,
            final_score=final_score,
            verdict=final_verdict,
            confidence=coverage_confidence,
            is_degraded=is_any_degraded,
            canonical_evidence=canonical_ev,
            combined_evidence_strings=string_ev,
            explanation=explanation,
        )



def fuse_detection_results(
    tier1_result: Any,
    tier2_result: Any,
    tier3_result: Optional[Any] = None,
    vision_result: Optional[Any] = None,
    established_partial_score: Optional[float] = None,
    established_verdict: Optional[str] = None,
) -> FusionResult:
    """Convenience alias for FusionEngine.fuse"""
    return FusionEngine.fuse(
        tier1_result=tier1_result,
        tier2_result=tier2_result,
        tier3_result=tier3_result,
        vision_result=vision_result,
        established_partial_score=established_partial_score,
        established_verdict=established_verdict,
    )
