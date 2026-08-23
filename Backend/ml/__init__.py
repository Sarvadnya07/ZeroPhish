"""
ZeroPhish ML Architecture Package.
"""

from __future__ import annotations

from .fusion import FusionResult, FusionSignal, RiskFusionEngine
from .predictor import MockPhishingPredictor, TextPredictor
from .url_predictor import (
    MockURLPredictor,
    ONNXURLPredictor,
    URLBERTPredictor,
    URLPredictionResult,
    URLPredictor,
    get_onnx_url_predictor,
    get_urlbert_predictor,
)
from .url_preprocessor import URLPreprocessor

__all__ = [
    "RiskFusionEngine",
    "FusionResult",
    "FusionSignal",
    "TextPredictor",
    "MockPhishingPredictor",
    "URLPredictor",
    "URLPredictionResult",
    "URLBERTPredictor",
    "ONNXURLPredictor",
    "MockURLPredictor",
    "URLPreprocessor",
    "get_urlbert_predictor",
    "get_onnx_url_predictor",
]
