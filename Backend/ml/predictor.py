"""
ML Predictor interface and deterministic mock predictors for testing and inference.

Defines the TextPredictor protocol and a simple mock implementation for unit tests.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger(__name__)

# Constants
DEFAULT_PHISHING_SCORE = 85.0
DEFAULT_PHISHING_CATEGORY = "phishing"


@runtime_checkable
class TextPredictor(Protocol):
    """
    Protocol for text‑based threat predictors.

    Implementations should provide asynchronous prediction and health checks.
    """

    async def predict(self, text: str) -> Tuple[float, str]:
        """
        Predict threat score and category from text input.

        Returns:
            (threat_score 0‑100, confidence_category: 'phishing' | 'safe' | 'spam' | 'unknown')
        """
        ...

    def is_loaded(self) -> bool:
        """Return True if the model is loaded and ready."""
        ...


class MockPhishingPredictor:
    """
    Deterministic mock predictor for unit tests without network or GPU.

    Behaves as a simple keyword‑based classifier.
    """

    def __init__(
        self,
        default_score: float = DEFAULT_PHISHING_SCORE,
        default_category: str = DEFAULT_PHISHING_CATEGORY,
    ) -> None:
        self.default_score = default_score
        self.default_category = default_category
        self._loaded = True
        logger.debug("MockPhishingPredictor initialized (score=%.1f, category=%s)",
                     default_score, default_category)

    def is_loaded(self) -> bool:
        return self._loaded

    async def predict(self, text: str) -> Tuple[float, str]:
        """
        Simulate prediction based on simple keyword matching.

        Args:
            text: Input text (URL, email body, etc.)

        Returns:
            (score, category)
        """
        if not text or not text.strip():
            return 0.0, "safe"

        lowered = text.lower()
        if "safe" in lowered or "legitimate" in lowered:
            return 5.0, "safe"
        if "urgent" in lowered or "verify" in lowered or "password" in lowered:
            return self.default_score, self.default_category
        return 50.0, "spam"