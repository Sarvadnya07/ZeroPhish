"""
ML Predictor interface and deterministic mock predictors for testing and inference.
"""
from __future__ import annotations

import logging
from typing import Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class TextPredictor(Protocol):
    async def predict(self, text: str) -> Tuple[float, str]:
        """Return (threat_score 0-100, confidence_category 'phishing'|'safe'|'spam')."""
        ...

    def is_loaded(self) -> bool:
        ...


class MockPhishingPredictor:
    """Deterministic mock predictor for unit tests without network or GPU."""

    def __init__(self, default_score: float = 85.0, default_category: str = "phishing"):
        self.default_score = default_score
        self.default_category = default_category
        self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded

    async def predict(self, text: str) -> Tuple[float, str]:
        if not text or not text.strip():
            return 0.0, "safe"
        lowered = text.lower()
        if "safe" in lowered or "legitimate" in lowered:
            return 5.0, "safe"
        if "urgent" in lowered or "verify" in lowered or "password" in lowered:
            return self.default_score, self.default_category
        return 50.0, "spam"
