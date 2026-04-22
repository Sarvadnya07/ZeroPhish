class WeightedScoreEngine:
    @staticmethod
    def clamp_score(score: float) -> float:
        return max(0.0, min(100.0, float(score)))

    @staticmethod
    def round_score(score: float) -> float:
        return round(WeightedScoreEngine.clamp_score(score), 2)

    @staticmethod
    def determine_verdict(score: float) -> str:
        if score < 30:
            return "SAFE"
        if score < 70:
            return "SUSPICIOUS"
        return "CRITICAL"

    @staticmethod
    def determine_threat_status(score: float) -> str:
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "SUSPICIOUS"
        return "OK"

    @staticmethod
    def calculate_weighted_score(scores: list[float], weights: list[float]) -> float:
        """
        Unified weighted score calculation with fallback to simple average.
        Ensures final score is clamped between 0 and 100.
        """
        if not scores:
            return 0.0

        if len(scores) != len(weights):
            raise ValueError("Scores and weights must have the same length")

        total_weight = sum(weights)
        if total_weight <= 0:
            return WeightedScoreEngine.clamp_score(sum(scores) / len(scores))

        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        return WeightedScoreEngine.clamp_score(weighted_sum / total_weight)

    @staticmethod
    def calculate_partial_score(tier1_score: float, tier2_score: float, weights) -> float:
        return WeightedScoreEngine.calculate_weighted_score(
            [tier1_score, tier2_score], [weights.tier1, weights.tier2]
        )

    @staticmethod
    def calculate_final_score(tier1_score: float, tier2_score: float, tier3_score: float, weights) -> float:
        return WeightedScoreEngine.calculate_weighted_score(
            [tier1_score, tier2_score, tier3_score],
            [weights.tier1, weights.tier2, weights.tier3],
        )

    @staticmethod
    def merge_evidence(
        tier1_evidence: list[str], tier2_evidence: list[str], tier3_flagged_phrases: list[str] | None
    ) -> list[str]:
        merged: list[str] = []

        for item in tier1_evidence:
            text = str(item).strip()
            if text:
                merged.append(text)

        for item in tier2_evidence:
            text = str(item).strip()
            if text:
                merged.append(text)

        for phrase in tier3_flagged_phrases or []:
            text = str(phrase).strip()
            if text:
                merged.append(f"AI: {text}")

        deduped: list[str] = []
        seen: set[str] = set()
        for item in merged:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped
