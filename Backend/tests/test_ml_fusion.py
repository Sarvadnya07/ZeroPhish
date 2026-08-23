"""
Unit tests for Backend/ml/fusion.py and Backend/ml/predictor.py.
"""

import pytest

from ml.fusion import FusionResult, RiskFusionEngine
from ml.predictor import MockPhishingPredictor


def test_risk_fusion_weighted_calculation():
    """Test standard 3-tier weighted formula: (T1 * 0.2) + (T2 * 0.3) + (T3 * 0.5)."""
    # 20 * 0.2 + 40 * 0.3 + 80 * 0.5 = 4 + 12 + 40 = 56.0
    res = RiskFusionEngine.fuse(tier1_score=20.0, tier2_score=40.0, tier3_score=80.0)
    assert res.final_score == 56.0
    assert res.verdict == "SUSPICIOUS"
    assert res.confidence == 0.92
    assert res.hard_override_applied is None


def test_risk_fusion_partial_tier2():
    """Test partial fusion without Tier 3."""
    # (10 * 0.2 + 20 * 0.3) / 0.5 = (2 + 6) / 0.5 = 16.0
    res = RiskFusionEngine.fuse(tier1_score=10.0, tier2_score=20.0, tier3_score=None)
    assert res.final_score == 16.0
    assert res.verdict == "SAFE"
    assert res.confidence == 0.75


def test_risk_fusion_critical_verdict():
    """Test score >= 70 yields CRITICAL verdict."""
    res = RiskFusionEngine.fuse(tier1_score=80.0, tier2_score=90.0, tier3_score=85.0)
    assert res.final_score >= 70.0
    assert res.verdict == "CRITICAL"


def test_risk_fusion_hard_malicious_override():
    """Test hard security rule override immediately sets CRITICAL."""
    res = RiskFusionEngine.fuse(
        tier1_score=10.0,
        tier2_score=10.0,
        tier3_score=10.0,
        hard_malicious_triggers=["Known active ransomware C2 domain"],
    )
    assert res.final_score == 95.0
    assert res.verdict == "CRITICAL"
    assert res.hard_override_applied is not None
    assert "Known active ransomware" in res.hard_override_applied


def test_risk_fusion_hard_safe_override():
    """Test verified allowlist override sets SAFE."""
    res = RiskFusionEngine.fuse(
        tier1_score=40.0,
        tier2_score=50.0,
        hard_safe_triggers=["Internal corporate intranet verified SPF/DKIM"],
    )
    assert res.final_score == 5.0
    assert res.verdict == "SAFE"


@pytest.mark.asyncio
async def test_mock_phishing_predictor():
    """Test deterministic mock text predictor."""
    predictor = MockPhishingPredictor()
    assert predictor.is_loaded() is True

    score_safe, cat_safe = await predictor.predict("This is a safe and legitimate email")
    assert score_safe == 5.0
    assert cat_safe == "safe"

    score_phish, cat_phish = await predictor.predict("Urgent: verify your password right away")
    assert score_phish == 85.0
    assert cat_phish == "phishing"

    score_empty, cat_empty = await predictor.predict("")
    assert score_empty == 0.0
    assert cat_empty == "safe"
