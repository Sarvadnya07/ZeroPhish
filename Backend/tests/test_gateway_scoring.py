import pytest
from gateway import (
    _calculate_weighted_score, 
    _clamp_score, 
    _calculate_partial_score, 
    _calculate_final_score, 
    _determine_threat_status, 
    _merge_evidence,
    WEIGHTS
)

def test_clamp_score():
    """Test that scores are constrained between 0 and 100."""
    assert _clamp_score(50.0) == 50.0
    assert _clamp_score(150.0) == 100.0
    assert _clamp_score(-10.0) == 0.0

def test_weighted_score_basic():
    """Test basic weighted score calculation."""
    # 0.2 * 10 + 0.3 * 20 = 2 + 6 = 8. Total weight 0.5. 8 / 0.5 = 16
    assert _calculate_weighted_score([10.0, 20.0], [0.2, 0.3]) == pytest.approx(16.0)

def test_weighted_score_total_one():
    """Test weighted score where weights sum to 1.0."""
    # 0.2 * 10 + 0.3 * 20 + 0.5 * 30 = 2 + 6 + 15 = 23. Total weight 1.0. 23 / 1.0 = 23
    assert _calculate_weighted_score([10.0, 20.0, 30.0], [0.2, 0.3, 0.5]) == pytest.approx(23.0)

def test_weighted_score_clamping():
    """Test that the result is clamped between 0 and 100."""
    assert _calculate_weighted_score([110.0, 120.0], [0.5, 0.5]) == 100.0
    assert _calculate_weighted_score([-10.0, -20.0], [0.5, 0.5]) == 0.0

def test_weighted_score_zero_weights():
    """Test that it falls back to simple average if total weight is <= 0."""
    # Should fallback to average: (10 + 20) / 2 = 15
    assert _calculate_weighted_score([10.0, 20.0], [0.0, 0.0]) == pytest.approx(15.0)

def test_weighted_score_mismatched_lengths():
    """Test that ValueError is raised when lengths mismatch."""
    with pytest.raises(ValueError, match="Scores and weights must have the same length"):
        _calculate_weighted_score([10.0, 20.0], [0.2])

def test_weighted_score_empty():
    """Test that empty scores list returns 0.0."""
    assert _calculate_weighted_score([], []) == 0.0

def test_calculate_partial_score():
    """Test partial score calculation using predefined weights."""
    tier1_score = 10.0
    tier2_score = 20.0
    expected_score = _calculate_weighted_score([tier1_score, tier2_score], [WEIGHTS.tier1, WEIGHTS.tier2])
    assert _calculate_partial_score(tier1_score, tier2_score) == expected_score

def test_calculate_final_score():
    """Test final score calculation across all tiers."""
    tier1_score = 10.0
    tier2_score = 20.0
    tier3_score = 30.0
    expected_score = _calculate_weighted_score(
        [tier1_score, tier2_score, tier3_score], 
        [WEIGHTS.tier1, WEIGHTS.tier2, WEIGHTS.tier3]
    )
    assert _calculate_final_score(tier1_score, tier2_score, tier3_score) == expected_score

def test_determine_threat_status():
    """Test categorical threat status based on score thresholds."""
    assert _determine_threat_status(70.0) == "CRITICAL"
    assert _determine_threat_status(85.5) == "CRITICAL"
    assert _determine_threat_status(40.0) == "SUSPICIOUS"
    assert _determine_threat_status(55.5) == "SUSPICIOUS"
    assert _determine_threat_status(39.9) == "OK"
    assert _determine_threat_status(10.0) == "OK"

def test_merge_evidence():
    """Test evidence merging with deduplication and AI prefixing."""
    tier1 = ["T1 evidence 1", "T1 evidence 2"]
    tier2 = ["T2 evidence 1", "T1 evidence 2"] # duplicate to test dedup
    tier3 = ["T3 phrase 1"]

    merged = _merge_evidence(tier1, tier2, tier3)

    assert "T1 evidence 1" in merged
    assert "T1 evidence 2" in merged
    assert "T2 evidence 1" in merged
    assert "AI: T3 phrase 1" in merged
    assert merged.count("T1 evidence 2") == 1
    assert len(merged) == 4

def test_merge_evidence_empty():
    """Test merging with empty or whitespace-only evidence."""
    assert _merge_evidence([], [], None) == []
    assert _merge_evidence([" "], ["\n"], ["\t"]) == []