"""
URL ML Predictor Implementations.
Provides typed URL predictors for URLBERT (Transformers) and LinearSVM (ONNX),
with strict fallback handling, bounded latency, and zero network calls during inference.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional, Protocol, runtime_checkable

import numpy as np
from pydantic import BaseModel, Field

from .url_preprocessor import URLPreprocessor

logger = logging.getLogger(__name__)

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    TRANSFORMERS_AVAILABLE = True
except ImportError:
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    TRANSFORMERS_AVAILABLE = False

try:
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ort = None
    ONNX_AVAILABLE = False

from enum import Enum
from typing import Optional, Protocol, runtime_checkable

import numpy as np
from pydantic import BaseModel, Field

from .url_preprocessor import URLPreprocessor

logger = logging.getLogger(__name__)


class ModelHealthState(str, Enum):
    MODEL_READY = "MODEL_READY"
    MODEL_LOADING = "MODEL_LOADING"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_FALLBACK = "MODEL_FALLBACK"
    MODEL_ERROR = "MODEL_ERROR"


class URLPredictionResult(BaseModel):
    """Structured result of a URL ML model inference."""

    score: float = Field(..., ge=0.0, le=100.0)
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    label: str  # "safe" | "suspicious" | "phishing" | "unknown"
    model_id: str
    model_version: str = "1.0.0"
    confidence: float = Field(..., ge=0.0, le=1.0)
    latency_ms: float = Field(..., ge=0.0)
    fallback_used: bool = False
    error: Optional[str] = None


@runtime_checkable
class URLPredictor(Protocol):
    """Protocol for URL ML Predictors."""

    async def predict(self, url: str) -> URLPredictionResult:
        """Run ML prediction on a URL string."""
        ...

    def is_loaded(self) -> bool:
        """Check if model is currently loaded in memory."""
        ...

    def get_health_state(self) -> ModelHealthState:
        """Return explicit health state."""
        ...

    async def predict(self, url: str) -> URLPredictionResult:
        """Run ML prediction on a URL string."""
        ...

    def is_loaded(self) -> bool:
        """Check if model is currently loaded in memory."""
        ...


class URLBERTPredictor:
    """
    Primary URL Classifier using URLBERT-tiny (CrabInHoney/urlbert-tiny-v4-phishing-classifier).
    Lightweight BERT architecture optimized for URL tokens.
    """

    def __init__(
        self,
        model_name: str = "CrabInHoney/urlbert-tiny-v4-phishing-classifier",
        cache_dir: str = "./models",
        inference_timeout: float = 2.0,
    ):
        self.model_name = model_name
        self.cache_dir = cache_dir
        self.inference_timeout = inference_timeout
        self.model = None
        self.tokenizer = None
        self.device = (
            "cuda" if (torch and hasattr(torch, "cuda") and torch.cuda.is_available()) else "cpu"
        )
        self._loaded = False

    async def load_model(self) -> bool:
        """Load tokenizer and model weights asynchronously."""
        if self._loaded:
            return True

        if not TRANSFORMERS_AVAILABLE or not torch or not AutoTokenizer:
            logger.warning("Transformers / PyTorch not available for URLBERT.")
            self._loaded = False
            return False

        try:
            logger.info("🤖 Loading URLBERT model: %s on %s", self.model_name, self.device)

            def _load():
                tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name,
                    cache_dir=self.cache_dir,
                    trust_remote_code=False,
                )
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name,
                    cache_dir=self.cache_dir,
                    trust_remote_code=False,
                )
                if hasattr(model, "to"):
                    model.to(self.device)
                if hasattr(model, "eval"):
                    model.eval()
                return tokenizer, model

            self.tokenizer, self.model = await asyncio.to_thread(_load)
            self._loaded = True
            logger.info("✅ URLBERT model loaded successfully.")
            return True

        except Exception as e:
            logger.error("❌ Failed to load URLBERT model: %s", e, exc_info=True)
            self._loaded = False
            return False

    async def predict(self, url: str) -> URLPredictionResult:
        """Predict phishing probability for a URL string."""
        start_time = time.perf_counter()
        cleaned_url = URLPreprocessor.preprocess(url)

        if not cleaned_url:
            return URLPredictionResult(
                score=0.0,
                phishing_probability=0.0,
                label="safe",
                model_id=self.model_name,
                confidence=1.0,
                latency_ms=0.0,
                fallback_used=False,
            )

        if not self._loaded:
            loaded = await self.load_model()
            if not loaded:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return URLPredictionResult(
                    score=50.0,
                    phishing_probability=0.5,
                    label="unknown",
                    model_id=self.model_name,
                    confidence=0.5,
                    latency_ms=round(elapsed_ms, 2),
                    fallback_used=True,
                    error="Model not loaded",
                )

        try:

            def _inference():
                inputs = self.tokenizer(
                    cleaned_url,
                    return_tensors="pt",
                    truncation=True,
                    max_length=128,
                    padding=True,
                )
                if hasattr(inputs, "items"):
                    inputs = {
                        k: (v.to(self.device) if hasattr(v, "to") else v) for k, v in inputs.items()
                    }

                if torch:
                    with torch.no_grad():
                        outputs = self.model(**inputs)
                        logits = outputs.logits
                        probabilities = torch.softmax(logits, dim=-1)
                    if hasattr(probabilities, "cpu"):
                        return probabilities.cpu().numpy()[0]
                return [0.5, 0.5]

            probs = await asyncio.wait_for(
                asyncio.to_thread(_inference), timeout=self.inference_timeout
            )

            phishing_prob = float(probs[1]) if len(probs) == 2 else float(max(probs))
            score = round(phishing_prob * 100.0, 2)

            if score < 30.0:
                label = "safe"
                conf = 1.0 - (score / 100.0)
            elif score < 70.0:
                label = "suspicious"
                conf = 0.70
            else:
                label = "phishing"
                conf = score / 100.0

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return URLPredictionResult(
                score=score,
                phishing_probability=round(phishing_prob, 4),
                label=label,
                model_id=self.model_name,
                confidence=round(conf, 2),
                latency_ms=round(elapsed_ms, 2),
                fallback_used=False,
            )

        except asyncio.TimeoutError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("⏱️ URLBERT inference timeout after %ss", self.inference_timeout)
            return URLPredictionResult(
                score=50.0,
                phishing_probability=0.5,
                label="unknown",
                model_id=self.model_name,
                confidence=0.5,
                latency_ms=round(elapsed_ms, 2),
                fallback_used=True,
                error="Timeout",
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("❌ URLBERT inference error: %s", e, exc_info=True)
            return URLPredictionResult(
                score=50.0,
                phishing_probability=0.5,
                label="unknown",
                model_id=self.model_name,
                confidence=0.5,
                latency_ms=round(elapsed_ms, 2),
                fallback_used=True,
                error=str(e),
            )

    def is_loaded(self) -> bool:
        return self._loaded

    def get_health_state(self) -> ModelHealthState:
        if self._loaded:
            return ModelHealthState.MODEL_READY
        if not TRANSFORMERS_AVAILABLE:
            return ModelHealthState.MODEL_UNAVAILABLE
        return ModelHealthState.MODEL_FALLBACK


class ONNXURLPredictor:
    """
    Baseline URL Classifier using pirocheto/phishing-url-detection in ONNX format.
    LinearSVM with string n-gram features for sub-millisecond CPU inference.
    """

    def __init__(
        self,
        model_path: str = "./models/pirocheto_onnx/model.onnx",
        model_name: str = "pirocheto/phishing-url-detection",
        inference_timeout: float = 1.0,
    ):
        self.model_path = model_path
        self.model_name = model_name
        self.inference_timeout = inference_timeout
        self.session = None
        self._loaded = False

    async def load_model(self) -> bool:
        if self._loaded:
            return True

        if not ONNX_AVAILABLE or not ort:
            logger.warning("ONNX Runtime is not available.")
            self._loaded = False
            return False

        if not os.path.exists(self.model_path):
            logger.info("ONNX model file not found at %s. Baseline ONNX disabled.", self.model_path)
            self._loaded = False
            return False

        try:

            def _load():
                return ort.InferenceSession(self.model_path, providers=["CPUExecutionProvider"])

            self.session = await asyncio.to_thread(_load)
            self._loaded = True
            logger.info("✅ ONNX URL model loaded from %s", self.model_path)
            return True
        except Exception as e:
            logger.error("❌ Failed to load ONNX model: %s", e)
            self._loaded = False
            return False

    async def predict(self, url: str) -> URLPredictionResult:
        start_time = time.perf_counter()
        cleaned_url = URLPreprocessor.preprocess(url)

        if not cleaned_url:
            return URLPredictionResult(
                score=0.0,
                phishing_probability=0.0,
                label="safe",
                model_id=self.model_name,
                confidence=1.0,
                latency_ms=0.0,
                fallback_used=False,
            )

        if not self._loaded:
            loaded = await self.load_model()
            if not loaded:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return URLPredictionResult(
                    score=50.0,
                    phishing_probability=0.5,
                    label="unknown",
                    model_id=self.model_name,
                    confidence=0.5,
                    latency_ms=round(elapsed_ms, 2),
                    fallback_used=True,
                    error="ONNX model not loaded",
                )

        try:

            def _inference():
                inputs = np.array([cleaned_url], dtype=object)
                input_name = self.session.get_inputs()[0].name
                outputs = self.session.run(None, {input_name: inputs})
                # Output[1] contains list of dict probabilities [{0: prob_safe, 1: prob_phish}]
                if len(outputs) > 1 and len(outputs[1]) > 0:
                    prob_dict = outputs[1][0]
                    return float(prob_dict.get(1, 0.5))
                return 0.5

            phishing_prob = await asyncio.wait_for(
                asyncio.to_thread(_inference), timeout=self.inference_timeout
            )
            score = round(phishing_prob * 100.0, 2)

            if score < 30.0:
                label = "safe"
            elif score < 70.0:
                label = "suspicious"
            else:
                label = "phishing"

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return URLPredictionResult(
                score=score,
                phishing_probability=round(phishing_prob, 4),
                label=label,
                model_id=self.model_name,
                confidence=0.90,
                latency_ms=round(elapsed_ms, 2),
                fallback_used=False,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return URLPredictionResult(
                score=50.0,
                phishing_probability=0.5,
                label="unknown",
                model_id=self.model_name,
                confidence=0.5,
                latency_ms=round(elapsed_ms, 2),
                fallback_used=True,
                error=str(e),
            )

    def is_loaded(self) -> bool:
        return self._loaded

    def get_health_state(self) -> ModelHealthState:
        if self._loaded:
            return ModelHealthState.MODEL_READY
        if not ONNX_AVAILABLE or not os.path.exists(self.model_path):
            return ModelHealthState.MODEL_UNAVAILABLE
        return ModelHealthState.MODEL_FALLBACK


class MockURLPredictor:
    """Deterministic Mock URL Predictor for testing."""

    def __init__(self, model_id: str = "mock-url-predictor"):
        self.model_id = model_id
        self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded

    def get_health_state(self) -> ModelHealthState:
        return ModelHealthState.MODEL_READY if self._loaded else ModelHealthState.MODEL_UNAVAILABLE

    async def predict(self, url: str) -> URLPredictionResult:
        if not url:
            return URLPredictionResult(
                score=0.0,
                phishing_probability=0.0,
                label="safe",
                model_id=self.model_id,
                confidence=1.0,
                latency_ms=0.5,
                fallback_used=False,
            )

        lowered = url.lower()
        if (
            "phish" in lowered
            or "malicious" in lowered
            or "paypa1" in lowered
            or "account-verify" in lowered
        ):
            return URLPredictionResult(
                score=92.0,
                phishing_probability=0.92,
                label="phishing",
                model_id=self.model_id,
                confidence=0.95,
                latency_ms=1.2,
                fallback_used=False,
            )
        elif "suspicious" in lowered or "warning" in lowered:
            return URLPredictionResult(
                score=55.0,
                phishing_probability=0.55,
                label="suspicious",
                model_id=self.model_id,
                confidence=0.70,
                latency_ms=1.1,
                fallback_used=False,
            )
        return URLPredictionResult(
            score=5.0,
            phishing_probability=0.05,
            label="safe",
            model_id=self.model_id,
            confidence=0.98,
            latency_ms=0.8,
            fallback_used=False,
        )


# Global singleton getters
_urlbert_instance: Optional[URLBERTPredictor] = None
_onnx_url_instance: Optional[ONNXURLPredictor] = None


async def get_urlbert_predictor() -> URLBERTPredictor:
    global _urlbert_instance
    if _urlbert_instance is None:
        model_name = os.getenv(
            "URLBERT_MODEL_NAME", "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
        )
        cache_dir = os.getenv("HF_MODEL_CACHE_DIR", "./models")
        _urlbert_instance = URLBERTPredictor(model_name=model_name, cache_dir=cache_dir)
        await _urlbert_instance.load_model()
    return _urlbert_instance


async def get_onnx_url_predictor() -> ONNXURLPredictor:
    global _onnx_url_instance
    if _onnx_url_instance is None:
        model_path = os.getenv("ONNX_URL_MODEL_PATH", "./models/pirocheto_onnx/model.onnx")
        _onnx_url_instance = ONNXURLPredictor(model_path=model_path)
        await _onnx_url_instance.load_model()
    return _onnx_url_instance
