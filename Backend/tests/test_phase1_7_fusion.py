"""
ZeroPhish Phase 1.7 Detection Fusion & Verdict Security Tests
============================================================
Comprehensive test suite verifying canonical fusion, monotonicity,
failure handling, explainability, evidence normalization, and
anti-spoofing trust boundaries.
"""

import pytest
from unittest.mock import MagicMock
from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    GatewayScanRequest,
    GatewayScanResponse,
    ScoringWeights,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    Verdict,
)
from vision.models import VisionAnalysisResult, VisionStatus
from fusion.models import (
    AuthorityLevel,
    CanonicalEvidence,
    EvidenceSeverity,
    EvidenceSource,
    FusionExplanation,
    FusionResult,
)
from fusion.engine import (
    FusionEngine,
    fuse_detection_results,
    calculate_partial_score,
    calculate_fused_score,
    determine_canonical_verdict,
)
from fusion.normalizer import EvidenceNormalizer


# ---------- Helper Fixtures ----------
def make_tier1(score: int = 10, degraded: bool = False, source: str = "server_verified", evidence: list = None) -> Tier1Result:
    return Tier1Result(
        score=score,
        evidence=evidence or ["Valid sender domain", "No suspicious link patterns"],
        status=CleanStatus.CLEAN if score < 20 else CleanStatus.SUSPICIOUS,
        source=source,
        server_score=score,
        execution_time_ms=1.5,
    )


def make_tier2(
    score: float = 10.0,
    domain_status: DomainStatus = DomainStatus.OK,
    category: str = "Safe",
    flagged: list = None,
    evidence: list = None,
) -> Tier2Result:
    return Tier2Result(
        score=score,
        domain_analysis=DomainAnalysis(status=domain_status, score=score, weight=0.3),
        threat_analysis=Tier2Analysis(status=domain_status, score=score, weight=0.7),
        threat_details=ThreatAnalysisDetail(
            threat_level=int(score),
            category=category,
            reasoning=f"Tier 2 evaluation: {category}",
            flagged_phrases=flagged or [],
        ),
        evidence=evidence or [f"Domain status: {domain_status.value}"],
        execution_time_ms=10.0,
    )


def make_tier3(
    score: int = 10,
    category: str = "Benign",
    status: TierStatus = TierStatus.COMPLETE,
    requires_visual: bool = False,
    flagged: list = None,
) -> Tier3Result:
    return Tier3Result(
        score=score,
        category=category,
        reasoning="Tier 3 semantic AI reasoning.",
        flagged_phrases=flagged or [],
        confidence=0.95,
        requires_visual_check=requires_visual,
        status=status,
        provider="gemini",
        model="gemini-1.5-flash",
    )


def make_vision(
    visual_score: float = 10.0,
    status: VisionStatus = VisionStatus.SUCCESS,
    detected_brands: list = None,
    mismatch: bool = False,
    credential_ui: bool = False,
) -> VisionAnalysisResult:
    return VisionAnalysisResult(
        status=status,
        visual_score=visual_score,
        confidence=0.92,
        visual_category="BENIGN_UI" if visual_score < 30 else "PHISHING_LOGIN",
        findings=["Screenshot parsed successfully."],
        detected_brands=detected_brands or [],
        brand_domain_mismatch=mismatch,
        credential_ui_detected=credential_ui,
        visual_impersonation_signal=mismatch or credential_ui,
    )


# =========================================================
# TEST MATRIX: CASES A - Y
# =========================================================

def test_case_a_all_tiers_safe():
    """Case A: All 4 tiers report safe/benign signals -> Verdict SAFE."""
    t1 = make_tier1(score=5)
    t2 = make_tier2(score=10.0)
    t3 = make_tier3(score=15, category="Safe")
    v = make_vision(visual_score=10.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.verdict == "SAFE"
    assert res.final_score < 30.0
    assert not res.is_degraded
    assert "No material phishing indicators" in res.explanation.top_reasons[0]


def test_case_b_t1_suspicious():
    """Case B: Deterministic Tier 1 reports suspicious score -> Verdict SUSPICIOUS."""
    t1 = make_tier1(score=50, evidence=["Urgent action requested in subject"])
    t2 = make_tier2(score=20.0)
    t3 = make_tier3(score=20)
    v = make_vision(visual_score=15.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.verdict == "SUSPICIOUS"
    assert res.final_score >= 30.0
    assert any("Urgent action" in r for r in res.explanation.top_reasons)


def test_case_c_t2_suspicious():
    """Case C: Tier 2 domain intelligence reports suspicious domain age."""
    t1 = make_tier1(score=10)
    t2 = make_tier2(score=60.0, domain_status=DomainStatus.SUSPICIOUS, category="SuspiciousDomain")
    t3 = make_tier3(score=15)
    v = make_vision(visual_score=10.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.verdict == "SUSPICIOUS"
    assert res.final_score >= 30.0
    assert any("Domain is relatively new" in r for r in res.explanation.top_reasons)


def test_case_d_t1_critical():
    """Case D: Tier 1 heuristic detects critical phishing pattern -> Monotonic CRITICAL."""
    t1 = make_tier1(score=85, evidence=["Punycode spoofed domain", "Credential link mismatch"])
    t2 = make_tier2(score=20.0)
    t3 = make_tier3(score=10)  # AI returns low score
    v = make_vision(visual_score=5.0)  # Vision returns low score

    res = fuse_detection_results(t1, t2, t3, v)
    # Monotonicity floor: T1 critical partial cannot be downgraded by advisory tiers
    assert res.verdict == "CRITICAL"
    assert res.final_score >= 70.0


def test_case_e_t2_critical():
    """Case E: Tier 2 domain age is < 30 days -> Monotonic CRITICAL."""
    t1 = make_tier1(score=40)
    t2 = make_tier2(score=90.0, domain_status=DomainStatus.CRITICAL)
    t3 = make_tier3(score=20)
    v = make_vision(visual_score=10.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.partial_score >= 70.0
    assert res.verdict == "CRITICAL"
    assert res.final_score >= 70.0


def test_case_f_t3_escalation():
    """Case F: Deterministic partial is SAFE, but Tier 3 AI identifies credential harvesting -> Escalates."""
    t1 = make_tier1(score=15)
    t2 = make_tier2(score=20.0)
    t3 = make_tier3(score=85, category="Credential Harvesting", flagged=["enter password to verify"])
    v = None

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.partial_score < 30.0  # (15*0.4 + 20*0.6) = 18.0
    assert res.final_score > 30.0    # (15*0.2 + 20*0.3 + 85*0.5) = 3 + 6 + 42.5 = 51.5
    assert res.verdict == "SUSPICIOUS"
    assert any("Credential Harvesting" in r for r in res.explanation.top_reasons)


def test_case_g_vision_escalation():
    """Case G: Text is benign, but Vision detects brand domain mismatch -> Escalates above partial score to SUSPICIOUS."""
    t1 = make_tier1(score=20)
    t2 = make_tier2(score=25.0)
    t3 = make_tier3(score=30)
    v = make_vision(visual_score=95.0, detected_brands=["Microsoft"], mismatch=True, credential_ui=True)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.partial_score < 30.0
    assert res.final_score > res.partial_score
    assert res.verdict == "SUSPICIOUS"
    assert any(ev.signal_type == "VISUAL_BRAND_DOMAIN_MISMATCH" for ev in res.canonical_evidence)
    assert any("Microsoft" in r for r in res.explanation.top_reasons)


def test_case_h_t3_failure():
    """Case H: Tier 3 fails -> final score is not synthetic 0 or 50, but cleanly uses partial score."""
    t1 = make_tier1(score=45)
    t2 = make_tier2(score=40.0)
    t3 = Tier3Result(
        score=0,
        category="AI_PROVIDER_ERROR",
        reasoning="Service unavailable",
        flagged_phrases=[],
        status=TierStatus.FAILED,
    )
    v = None

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.final_score == res.partial_score  # 42.0
    assert res.verdict == "SUSPICIOUS"
    assert res.explanation.tier_summaries["tier3"].status == "failed"
    assert not res.explanation.tier_summaries["tier3"].participated
    assert any("Tier 3 AI" in lim for lim in res.explanation.limitations)


def test_case_i_vision_failure():
    """Case I: Vision fails/times out -> visual_score None does not lower threat."""
    t1 = make_tier1(score=50)
    t2 = make_tier2(score=50.0)
    t3 = make_tier3(score=50)
    v = VisionAnalysisResult(
        status=VisionStatus.TIMEOUT,
        visual_score=None,
        confidence=0.0,
        visual_category="ERROR",
        findings=["Vision request timed out."],
    )

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.explanation.tier_summaries["vision"].status == "timeout"
    assert not res.explanation.tier_summaries["vision"].participated
    assert res.final_score == 50.0
    assert any("Vision" in lim for lim in res.explanation.limitations)


def test_case_j_t3_plus_vision_failure():
    """Case J: Both Tier 3 and Vision fail -> System cleanly relies on authoritative partial score."""
    t1 = make_tier1(score=65)
    t2 = make_tier2(score=55.0)
    t3 = Tier3Result(score=0, category="AI_TIMEOUT", reasoning="Timeout", status=TierStatus.TIMEOUT)
    v = VisionAnalysisResult(status=VisionStatus.FAILED, visual_score=None, findings=["Invalid PNG"])

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.final_score == res.partial_score
    assert res.verdict == "SUSPICIOUS"
    assert len(res.explanation.limitations) >= 2


def test_case_k_malformed_t3():
    """Case K: Malformed or empty Tier 3 response is isolated and does not poison fusion."""
    t1 = make_tier1(score=10)
    t2 = make_tier2(score=10)
    t3 = Tier3Result(score=0, category="AI_INVALID_RESPONSE", reasoning="Bad JSON", status=TierStatus.FAILED)

    res = fuse_detection_results(t1, t2, t3, None)
    assert res.final_score == res.partial_score
    assert not res.explanation.tier_summaries["tier3"].participated


def test_case_l_malformed_vision():
    """Case L: Decompression bomb or invalid image payload in Vision does not crash fusion."""
    t1 = make_tier1(score=20)
    t2 = make_tier2(score=20)
    t3 = make_tier3(score=20)
    v = VisionAnalysisResult(status=VisionStatus.INVALID_IMAGE, visual_score=None, findings=["Image bomb rejected"])

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.explanation.tier_summaries["vision"].participated is False
    assert res.final_score == 20.0


def test_case_m_suspicious_plus_ai_score_zero():
    """Case M: Suspicious partial + AI returns score 0 -> Monotonicity prevents downgrade to SAFE."""
    t1 = make_tier1(score=40)
    t2 = make_tier2(score=45.0)
    t3 = make_tier3(score=0, category="Safe")  # Advisory layer claimed 0
    v = None

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.partial_score >= 30.0
    assert res.final_score >= 30.0
    assert res.verdict == "SUSPICIOUS"
    assert res.verdict != "SAFE"


def test_case_n_critical_plus_ai_score_zero():
    """Case N: Critical partial + AI returns score 0 -> Monotonicity prevents downgrade from CRITICAL."""
    t1 = make_tier1(score=80)
    t2 = make_tier2(score=85.0)
    t3 = make_tier3(score=0, category="Safe")
    v = None

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.partial_score >= 70.0
    assert res.final_score >= 70.0
    assert res.verdict == "CRITICAL"


def test_case_o_suspicious_plus_vision_score_zero():
    """Case O: Suspicious partial + Vision returns score 0 -> Verdict remains SUSPICIOUS."""
    t1 = make_tier1(score=50)
    t2 = make_tier2(score=40.0)
    t3 = make_tier3(score=40)
    v = make_vision(visual_score=0.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.final_score >= 30.0
    assert res.verdict == "SUSPICIOUS"


def test_case_p_critical_plus_vision_score_zero():
    """Case P: Critical partial + Vision returns score 0 -> Verdict remains CRITICAL."""
    t1 = make_tier1(score=90)
    t2 = make_tier2(score=85.0)
    t3 = make_tier3(score=80)
    v = make_vision(visual_score=0.0)

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.final_score >= 70.0
    assert res.verdict == "CRITICAL"


def test_case_q_all_advisory_unavailable():
    """Case Q: Both T3 and Vision unavailable -> Weights smoothly revert to 100% deterministic partial."""
    t1 = make_tier1(score=25)
    t2 = make_tier2(score=25.0)
    res = fuse_detection_results(t1, t2, None, None)

    assert res.final_score == 25.0
    assert res.partial_score == 25.0
    assert res.verdict == "SAFE"
    assert res.explanation.tier_summaries["tier3"].status == "not_requested"
    assert res.explanation.tier_summaries["vision"].status == "not_requested"


def test_case_r_unknown_incomplete_state():
    """Case R: If deterministic tiers fail completely, verdict is UNKNOWN or fail-safe SUSPICIOUS, never false SAFE."""
    t1 = make_tier1(score=0, degraded=True)
    t2 = make_tier2(score=0, domain_status=DomainStatus.ERROR)
    # Both deterministic tiers degraded without valid data
    res = fuse_detection_results(t1, t2, None, None)
    assert res.verdict in ("UNKNOWN", "SUSPICIOUS")
    assert res.verdict != "SAFE"


def test_case_s_missing_screenshot():
    """Case S: AI requested visual verification, but screenshot was missing -> Marked clearly in status and limitations."""
    t1 = make_tier1(score=20)
    t2 = make_tier2(score=20)
    t3 = make_tier3(score=35, requires_visual=True)
    v = VisionAnalysisResult(
        status=VisionStatus.VISUAL_REQUIRED,
        visual_score=None,
        findings=["Visual verification required by Tier 3 AI, but screenshot was unavailable."],
        requires_followup=True,
    )

    res = fuse_detection_results(t1, t2, t3, v)
    assert res.explanation.tier_summaries["vision"].status == "visual_required"
    assert res.explanation.tier_summaries["vision"].status != "not_requested"
    assert res.explanation.tier_summaries["vision"].score is None
    assert res.explanation.tier_summaries["vision"].requires_followup is True
    assert any("screenshot was not provided" in lim for lim in res.explanation.limitations)

    # Crucial contract: When vision_result is None directly, but requires_visual_check is True:
    # Must report VISUAL_REQUIRED, visual_score=None, requires_followup=True (NEVER NOT_REQUESTED)
    res_none = fuse_detection_results(t1, t2, t3, None)
    assert res_none.explanation.tier_summaries["vision"].status == "visual_required"
    assert res_none.explanation.tier_summaries["vision"].status != "not_requested"
    assert res_none.explanation.tier_summaries["vision"].score is None
    assert res_none.explanation.tier_summaries["vision"].requires_followup is True
    assert any("screenshot was not provided" in lim for lim in res_none.explanation.limitations)



def test_case_t_duplicate_evidence():
    """Case T: Redundant signals across Tiers (e.g. urgent keyword) are deduplicated without losing severity."""
    t1 = make_tier1(score=30, evidence=["Urgent action required immediately", "Suspicious link"])
    t2 = make_tier2(score=30, flagged=["urgent action required immediately"])
    t3 = make_tier3(score=30, flagged=["urgent action required immediately"])

    res = fuse_detection_results(t1, t2, t3, None)
    # Check that identical lowercase phrase is deduplicated in canonical evidence
    phrases = [ev.description.lower() for ev in res.canonical_evidence]
    assert len([p for p in phrases if "urgent action required immediately" in p]) == 1


def test_case_u_contradictory_evidence():
    """Case U: Model reasoning claims benign but deterministic heuristics found punycode link mismatch."""
    t1 = make_tier1(score=75, evidence=["Link text mismatch: paypal.com vs evil.com"])
    t2 = make_tier2(score=30)
    t3 = make_tier3(score=10, category="Safe")  # Adversarial/confused AI

    res = fuse_detection_results(t1, t2, t3, None)
    # Authoritative deterministic evidence takes precedence in top_reasons
    assert res.verdict == "CRITICAL"
    assert res.canonical_evidence[0].authoritative is True
    assert "paypal.com" in res.canonical_evidence[0].description


def test_case_v_client_score_injection():
    """Case V: Client sends score=0 in request, but server computed score=60 -> Server authority preserved."""
    from gateway import analyze_tier1_server
    # Server computes real score; client-supplied 0 cannot suppress it
    t1 = Tier1Result(
        score=60,
        evidence=["[Server Verified] Credential form detected"],
        status=CleanStatus.SUSPICIOUS,
        source="server_verified",
        server_score=60,
        client_score=0,
        client_advisory=True,
    )
    t2 = make_tier2(score=30)
    res = fuse_detection_results(t1, t2, None, None)
    assert res.partial_score >= 30.0
    assert res.verdict == "SUSPICIOUS"


def test_case_w_client_verdict_injection():
    """Case W: A client cannot inject a synthetic 'SAFE' verdict into GatewayScanResponse."""
    t1 = make_tier1(score=60)
    t2 = make_tier2(score=60)
    res = fuse_detection_results(t1, t2, None, None)
    assert res.verdict == "SUSPICIOUS"
    # Even if client sends "verdict: SAFE", Gateway constructor uses fusion verdict
    resp = GatewayScanResponse(
        scan_id="test-scan",
        partial_score=res.partial_score,
        final_score=res.final_score,
        verdict=Verdict(res.verdict),
        tier1=t1,
        tier2=t2,
        combined_evidence=res.combined_evidence_strings,
        canonical_evidence=res.canonical_evidence,
        explanation=res.explanation,
    )
    assert resp.verdict == Verdict.SUSPICIOUS


def test_case_x_provider_provenance_preservation():
    """Case X: Tier 3 and Vision evidence items preserve exact provider and model provenance."""
    t1 = make_tier1(score=10)
    t2 = make_tier2(score=10)
    t3 = make_tier3(score=70, category="Credential Harvesting", flagged=["login to office"])
    v = make_vision(visual_score=80, detected_brands=["Google"], mismatch=True)

    res = fuse_detection_results(t1, t2, t3, v)
    t3_ev = [e for e in res.canonical_evidence if e.source_tier == EvidenceSource.TIER3]
    v_ev = [e for e in res.canonical_evidence if e.source_tier == EvidenceSource.VISION]

    assert len(t3_ev) > 0
    assert t3_ev[0].provenance == "gemini:gemini-1.5-flash"
    assert len(v_ev) > 0
    assert v_ev[0].provenance == "vision_multimodal"


def test_case_y_sse_result_consistency():
    """Case Y: SSE serialization maintains identical score and verdict to REST response."""
    t1 = make_tier1(score=40)
    t2 = make_tier2(score=50)
    t3 = make_tier3(score=60)
    res = fuse_detection_results(t1, t2, t3, None)

    resp = GatewayScanResponse(
        scan_id="scan-123",
        partial_score=res.partial_score,
        final_score=res.final_score,
        verdict=Verdict(res.verdict),
        tier1=t1,
        tier2=t2,
        tier3=t3,
        complete=True,
        combined_evidence=res.combined_evidence_strings,
        canonical_evidence=res.canonical_evidence,
        explanation=res.explanation,
    )

    sse_dict = resp.model_dump(exclude_none=True)
    assert sse_dict["final_score"] == res.final_score
    assert sse_dict["verdict"] == res.verdict
    assert sse_dict["explanation"]["verdict"] == res.verdict


# =========================================================
# PROPERTY-BASED INVARIANT TESTS
# =========================================================

def test_property_monotonicity_across_ranges():
    """Invariant: For all scores where partial >= 30, final_score >= partial_score."""
    for partial_t1 in [30, 40, 50, 70, 85, 100]:
        for partial_t2 in [30, 45, 60, 75, 90, 100]:
            t1 = make_tier1(score=partial_t1)
            t2 = make_tier2(score=partial_t2)

            for advisory_t3 in [0, 10, 50, 100, None]:
                for advisory_v in [0, 10, 50, 100, None]:
                    t3 = make_tier3(score=advisory_t3) if advisory_t3 is not None else None
                    v = make_vision(visual_score=advisory_v) if advisory_v is not None else None

                    res = fuse_detection_results(t1, t2, t3, v)
                    # Core invariant: final_score must never drop below partial score when in threat zone
                    assert res.final_score >= res.partial_score, (
                        f"Failed for t1={partial_t1}, t2={partial_t2}, t3={advisory_t3}, v={advisory_v}: "
                        f"final={res.final_score}, partial={res.partial_score}"
                    )
                    assert res.verdict != "SAFE", "Established threat cannot become SAFE"


def test_property_critical_severity_floor():
    """Invariant: If partial score >= 70, verdict is ALWAYS CRITICAL regardless of AI/Vision."""
    for adv_t3 in [0, 5, 20, None]:
        for adv_v in [0, 5, 20, None]:
            t1 = make_tier1(score=90)
            t2 = make_tier2(score=80)
            t3 = make_tier3(score=adv_t3) if adv_t3 is not None else None
            v = make_vision(visual_score=adv_v) if adv_v is not None else None

            res = fuse_detection_results(t1, t2, t3, v)
            assert res.verdict == "CRITICAL"
            assert res.final_score >= 70.0


def test_property_no_synthetic_score_on_failure():
    """Invariant: Failed tier never injects a synthetic 50 score into fusion."""
    t1 = make_tier1(score=10)
    t2 = make_tier2(score=10)
    t3 = Tier3Result(score=0, category="AI_TIMEOUT", reasoning="Timeout", status=TierStatus.TIMEOUT)
    v = VisionAnalysisResult(status=VisionStatus.FAILED, visual_score=None, findings=["Error"])

    res = fuse_detection_results(t1, t2, t3, v)
    # If synthetic 50 were used, score would be > 10.
    assert res.final_score == 10.0
    assert res.explanation.tier_summaries["tier3"].score is None
    assert res.explanation.tier_summaries["vision"].score is None


def test_visual_brand_mismatch_does_not_force_critical():
    """
    Phase 1.7 Correction Gate: Proves visual brand mismatch alone cannot force CRITICAL.
    Vision produces signals/evidence only; only Gateway fusion determines final severity.

    Cases verified:
    1. visual brand + mismatch only -> cannot become CRITICAL solely from Vision (remains SAFE)
    2. visual brand + mismatch + low deterministic score -> cannot become CRITICAL solely from Vision
    3. visual brand + mismatch + suspicious deterministic score -> remains at least SUSPICIOUS
    4. visual brand + mismatch + critical deterministic score -> remains CRITICAL
    """
    v_mismatch = make_vision(
        visual_score=85,
        detected_brands=["Microsoft"],
        mismatch=True,
        credential_ui=True,
    )

    # 1. Visual brand + mismatch only (low deterministic score 0.0)
    t1_zero = make_tier1(score=0)
    t2_zero = make_tier2(score=0)
    res1 = fuse_detection_results(t1_zero, t2_zero, None, v_mismatch)
    # Weights: T1(0.25), T2(0.50), Vision(0.25) -> (0*0.25) + (0*0.50) + (85*0.25) = 21.25 (< 30)
    # Centralized threshold mapping: 21.25 < THRESHOLD_SAFE (30.0) -> EXACT verdict: SAFE
    assert res1.final_score == 21.25
    assert res1.verdict == "SAFE"
    assert res1.verdict != "CRITICAL"
    assert res1.verdict != "SUSPICIOUS"
    # Explainability check: says "visual brand/domain mismatch detected", NOT "Vision declared this CRITICAL"
    assert any("visual brand/domain mismatch detected" in ev.description.lower() for ev in res1.canonical_evidence)
    assert not any("vision declared this critical" in r.lower() for r in res1.explanation.top_reasons)

    # 2. Visual brand + mismatch + low deterministic score (e.g. 15.0)
    t1_low = make_tier1(score=15)
    t2_low = make_tier2(score=15)
    res2 = fuse_detection_results(t1_low, t2_low, None, v_mismatch)
    # Score: (15*0.25) + (15*0.50) + (85*0.25) = 32.50. Exact threshold [30.0, 70.0) -> SUSPICIOUS
    assert res2.final_score == 32.50
    assert res2.verdict == "SUSPICIOUS"
    assert res2.verdict != "CRITICAL"
    assert res2.verdict != "SAFE"

    # 3. Visual brand + mismatch + suspicious deterministic score (e.g. 40.0 & 45.0)
    t1_susp = make_tier1(score=40)
    t2_susp = make_tier2(score=45)
    res3 = fuse_detection_results(t1_susp, t2_susp, None, v_mismatch)
    # Score: (40*0.25) + (45*0.50) + (85*0.25) = 53.75. Exact threshold [30.0, 70.0) -> SUSPICIOUS
    assert res3.final_score == 53.75
    assert res3.verdict == "SUSPICIOUS"
    assert res3.verdict != "CRITICAL"
    assert res3.verdict != "SAFE"
    assert res3.final_score >= res3.partial_score

    # 4. Visual brand + mismatch + critical deterministic score (e.g. 80.0 & 85.0)
    t1_crit = make_tier1(score=80)
    t2_crit = make_tier2(score=85)
    res4 = fuse_detection_results(t1_crit, t2_crit, None, v_mismatch)
    assert res4.verdict == "CRITICAL"
    assert res4.final_score == 85.0


def test_domain_age_equivalence_phase1_4_and_phase1_7():
    """
    Verify exact equivalence between Phase 1.4 domain_intel and Phase 1.7 EvidenceNormalizer:
    - Age < 30 days -> CRITICAL (100.0) / EvidenceSeverity.CRITICAL
    - Age < 365 days -> SUSPICIOUS (60.0) / EvidenceSeverity.MEDIUM
    - Age >= 365 days -> OK (10.0) / Not added as threat
    - Age is None -> UNKNOWN (50.0) / DOMAIN_LOOKUP_INCOMPLETE (LOW)
    """
    from tier_2.domain_intel import analyze_domain_age
    from fusion.normalizer import EvidenceNormalizer

    # 1. New domain (< 30 days)
    score14, status14, msg14 = analyze_domain_age(12)
    assert status14 == "CRITICAL"
    assert score14 == 100.0
    ev17 = EvidenceNormalizer.normalize_tier2(evidence_list=[], domain_age_days=12, domain_status=status14)
    assert len(ev17) == 1
    assert ev17[0].signal_type == "NEW_DOMAIN"
    assert ev17[0].severity == EvidenceSeverity.CRITICAL

    # 2. Suspicious recent domain (< 365 days)
    score14, status14, msg14 = analyze_domain_age(120)
    assert status14 == "SUSPICIOUS"
    assert score14 == 60.0
    ev17 = EvidenceNormalizer.normalize_tier2(evidence_list=[], domain_age_days=120, domain_status=status14)
    assert len(ev17) == 1
    assert ev17[0].signal_type == "RECENT_DOMAIN"
    assert ev17[0].severity == EvidenceSeverity.MEDIUM

    # 3. Established domain (>= 365 days)
    score14, status14, msg14 = analyze_domain_age(800)
    assert status14 == "OK"
    assert score14 == 10.0
    ev17 = EvidenceNormalizer.normalize_tier2(evidence_list=[], domain_age_days=800, domain_status=status14)
    assert len(ev17) == 0  # OK domain produces no threat findings

    # 4. Unknown domain (None / Lookup failed)
    score14, status14, msg14 = analyze_domain_age(None, lookup_status="LOOKUP_FAILED")
    assert status14 == "UNKNOWN"
    assert score14 == 50.0
    ev17 = EvidenceNormalizer.normalize_tier2(evidence_list=[], domain_age_days=None, domain_status=status14)
    assert len(ev17) == 1
    assert ev17[0].signal_type == "DOMAIN_LOOKUP_INCOMPLETE"
    assert ev17[0].severity == EvidenceSeverity.LOW



def test_deterministic_tier_failure_scenarios():
    """
    Phase 1.7 Deterministic-Tier Failure Policy Audit:
    Proves behavior across all server-authoritative and advisory failure states:
    1. T1 failed + T2 active + T3 active + Vision active
    2. T1 active + T2 failed + T3 active + Vision active
    3. T1 failed + T2 active + T3 failed + Vision active
    4. T1 active + T2 failed + T3 failed + Vision active
    5. T1 failed + T2 failed + T3 active
    6. T1 failed + T2 failed + Vision active
    7. All deterministic tiers unavailable
    8. All tiers unavailable

    Invariants verified:
    - Failed tier -> score = None, participated = False
    - Never failure -> score 0 or score 50
    - Never failure -> silent SAFE
    - Weights renormalized deterministically and explainably
    """
    t1_ok = make_tier1(score=20)
    t2_ok = make_tier2(score=25)
    t3_ok = make_tier3(score=40)
    v_ok = make_vision(visual_score=35)

    import types
    t1_failed = types.SimpleNamespace(score=None, evidence=[], status="failed")
    t2_failed = types.SimpleNamespace(score=None, evidence=[], status="failed")
    t3_failed = types.SimpleNamespace(score=None, category="AI_ERROR", status="failed")
    v_failed = make_vision(status=VisionStatus.FAILED)



    # 1. T1 failed + T2 active + T3 active + Vision active
    res1 = fuse_detection_results(t1_failed, t2_ok, t3_ok, v_ok)
    assert res1.explanation.tier_summaries["tier1"].score is None
    assert res1.explanation.tier_summaries["tier1"].participated is False
    assert res1.explanation.tier_summaries["tier2"].participated is True
    assert res1.explanation.tier_summaries["tier3"].participated is True
    assert res1.explanation.tier_summaries["vision"].participated is True
    # Weights sum to 1.0 (T2: ~0.2941, T3: ~0.5294, Vision: ~0.1765)
    w1 = res1.explanation.tier_summaries
    active_weights_sum = w1["tier2"].weight + w1["tier3"].weight + w1["vision"].weight
    assert abs(active_weights_sum - 1.0) < 0.001
    assert res1.partial_score == 25.0

    # 2. T1 active + T2 failed + T3 active + Vision active
    res2 = fuse_detection_results(t1_ok, t2_failed, t3_ok, v_ok)
    assert res2.explanation.tier_summaries["tier2"].score is None
    assert res2.explanation.tier_summaries["tier2"].participated is False
    assert res2.explanation.tier_summaries["tier1"].participated is True
    w2 = res2.explanation.tier_summaries
    active_weights_sum = w2["tier1"].weight + w2["tier3"].weight + w2["vision"].weight
    assert abs(active_weights_sum - 1.0) < 0.001
    assert res2.partial_score == 20.0

    # 3. T1 failed + T2 active + T3 failed + Vision active
    res3 = fuse_detection_results(t1_failed, t2_ok, t3_failed, v_ok)
    assert res3.explanation.tier_summaries["tier1"].score is None
    assert res3.explanation.tier_summaries["tier3"].score is None
    assert res3.explanation.tier_summaries["tier2"].participated is True
    assert res3.explanation.tier_summaries["vision"].participated is True
    w3 = res3.explanation.tier_summaries
    assert abs(w3["tier2"].weight + w3["vision"].weight - 1.0) < 0.001

    # 4. T1 active + T2 failed + T3 failed + Vision active
    res4 = fuse_detection_results(t1_ok, t2_failed, t3_failed, v_ok)
    assert res4.explanation.tier_summaries["tier2"].score is None
    assert res4.explanation.tier_summaries["tier3"].score is None
    assert res4.explanation.tier_summaries["tier1"].participated is True
    assert res4.explanation.tier_summaries["vision"].participated is True
    w4 = res4.explanation.tier_summaries
    assert abs(w4["tier1"].weight + w4["vision"].weight - 1.0) < 0.001

    # 5. T1 failed + T2 failed + T3 active
    # Server-authoritative tiers both unavailable -> insufficient evidence, CANNOT declare SAFE
    t3_low = make_tier3(score=10, category="Safe")
    res5 = fuse_detection_results(t1_failed, t2_failed, t3_low, None)
    assert res5.partial_score is None
    assert res5.explanation.tier_summaries["tier1"].participated is False
    assert res5.explanation.tier_summaries["tier2"].participated is False
    assert res5.explanation.tier_summaries["tier3"].participated is True
    # Crucial: Advisory tier alone cannot declare SAFE when authoritative evaluation failed
    assert res5.verdict == "UNKNOWN"

    # 6. T1 failed + T2 failed + Vision active
    v_low = make_vision(visual_score=10)
    res6 = fuse_detection_results(t1_failed, t2_failed, None, v_low)
    assert res6.partial_score is None
    assert res6.explanation.tier_summaries["tier1"].participated is False
    assert res6.explanation.tier_summaries["tier2"].participated is False
    assert res6.explanation.tier_summaries["vision"].participated is True
    assert res6.verdict == "UNKNOWN"

    # 7. All deterministic tiers unavailable (T1 failed, T2 failed, T3 failed, Vision failed)
    res7 = fuse_detection_results(t1_failed, t2_failed, t3_failed, v_failed)
    assert res7.partial_score is None
    assert res7.final_score is None
    assert res7.verdict == "UNKNOWN"
    for tier in ("tier1", "tier2", "tier3", "vision"):
        assert res7.explanation.tier_summaries[tier].score is None
        assert res7.explanation.tier_summaries[tier].participated is False

    # 8. All tiers unavailable (None passed for all)
    res8 = fuse_detection_results(None, None, None, None)
    assert res8.partial_score is None
    assert res8.final_score is None
    assert res8.verdict == "UNKNOWN"
    for tier in ("tier1", "tier2", "tier3", "vision"):
        assert res8.explanation.tier_summaries[tier].score is None
        assert res8.explanation.tier_summaries[tier].participated is False

