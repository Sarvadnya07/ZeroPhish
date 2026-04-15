import pytest

from gateway import _calculate_weighted_score

def test_weighted_score_basic():
    # 0.2 * 10 + 0.3 * 20 = 2 + 6 = 8. Total weight 0.5. 8 / 0.5 = 16
    assert _calculate_weighted_score([10.0, 20.0], [0.2, 0.3]) == pytest.approx(16.0)

def test_weighted_score_total_one():
    # 0.2 * 10 + 0.3 * 20 + 0.5 * 30 = 2 + 6 + 15 = 23. Total weight 1.0. 23 / 1.0 = 23
    assert _calculate_weighted_score([10.0, 20.0, 30.0], [0.2, 0.3, 0.5]) == pytest.approx(23.0)

def test_weighted_score_clamping():
    assert _calculate_weighted_score([110.0, 120.0], [0.5, 0.5]) == 100.0
    assert _calculate_weighted_score([-10.0, -20.0], [0.5, 0.5]) == 0.0

def test_weighted_score_zero_weights():
    # Should fallback to average: (10 + 20) / 2 = 15
    assert _calculate_weighted_score([10.0, 20.0], [0.0, 0.0]) == pytest.approx(15.0)

def test_weighted_score_mismatched_lengths():
    with pytest.raises(ValueError, match="Scores and weights must have the same length"):
        _calculate_weighted_score([10.0, 20.0], [0.2])

def test_weighted_score_empty():
    assert _calculate_weighted_score([], []) == 0.0
