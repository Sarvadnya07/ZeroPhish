
import unittest

def _clamp_score(score: float) -> float:
    return max(0.0, min(100.0, float(score)))

def _calculate_weighted_score(scores: list[float], weights: list[float]) -> float:
    if not scores:
        return 0.0
    if len(scores) != len(weights):
        raise ValueError("Scores and weights must have the same length")
    total_weight = sum(weights)
    if total_weight <= 0:
        return _clamp_score(sum(scores) / len(scores))
    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    return _clamp_score(weighted_sum / total_weight)

class TestGatewayScoring(unittest.TestCase):
    def test_weighted_score_basic(self):
        # 0.2 * 10 + 0.3 * 20 = 2 + 6 = 8. Total weight 0.5. 8 / 0.5 = 16
        self.assertAlmostEqual(_calculate_weighted_score([10.0, 20.0], [0.2, 0.3]), 16.0)

    def test_weighted_score_total_one(self):
        # 0.2 * 10 + 0.3 * 20 + 0.5 * 30 = 2 + 6 + 15 = 23. Total weight 1.0. 23 / 1.0 = 23
        self.assertAlmostEqual(_calculate_weighted_score([10.0, 20.0, 30.0], [0.2, 0.3, 0.5]), 23.0)

    def test_weighted_score_clamping(self):
        self.assertEqual(_calculate_weighted_score([110.0, 120.0], [0.5, 0.5]), 100.0)
        self.assertEqual(_calculate_weighted_score([-10.0, -20.0], [0.5, 0.5]), 0.0)

    def test_weighted_score_zero_weights(self):
        # Should fallback to average: (10 + 20) / 2 = 15
        self.assertAlmostEqual(_calculate_weighted_score([10.0, 20.0], [0.0, 0.0]), 15.0)

    def test_weighted_score_mismatched_lengths(self):
        with self.assertRaises(ValueError):
            _calculate_weighted_score([10.0, 20.0], [0.2])

    def test_weighted_score_empty(self):
        self.assertEqual(_calculate_weighted_score([], []), 0.0)

if __name__ == '__main__':
    unittest.main()
