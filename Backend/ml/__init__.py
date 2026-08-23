"""
ZeroPhish ML Architecture Package.
"""
from __future__ import annotations

from .fusion import FusionResult, FusionSignal, RiskFusionEngine
from .predictor import MockPhishingPredictor, TextPredictor

__all__ = [
    "RiskFusionEngine",
    "FusionResult",
    "FusionSignal",
    "TextPredictor",
    "MockPhishingPredictor",
]
