"""
URL ML Predictor Implementations.

Provides typed URL predictors for URLBERT (Transformers) and LinearSVM (ONNX),
with strict fallback handling, bounded latency, and zero network calls during inference.

Includes the URLPredictor protocol, health states, and singleton getters.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from enum import Enum
from typing import Optional, Protocol, runtime_checkable, Any, cast
import types

import numpy as np
from pydantic import BaseModel, Field

from .url_preprocessor import URLPreprocessor

logger = logging.getLogger(__name__)

# ---------- Platform/Import Workarounds ----------
if sys.platform == "win32":
    # mypy/typing: set a dummy module instead of None to satisfy ModuleType expectation
    sys.modules.setdefault("torchvision", types.ModuleType("torchvision"))
    sys.modules.setdefault(
        "torchvision.transforms", types.ModuleType("torchvision.transforms")
    )

# ---------- Optional Imports ----------
try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except (ImportError, OSError, RuntimeError) as e:
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not available: %s", e)

try:
    import onnxruntime as ort  # type: ignore[import]
    ONNX_AVAILABLE = True
except ImportError as e:
    ort = None
    ONNX_AVAILABLE = False
    logger.warning("ONNX Runtime not available: %s", e)

# Cast optional imports to Any to help static analysis (Pylance) understand
# that we intentionally handle missing modules at runtime.
torch = cast(Any, globals().get("torch", None))
AutoTokenizer = cast(Any, globals().get("AutoTokenizer", None))
AutoModelForSequenceClassification = cast(Any, globals().get("AutoModelForSequenceClassification", None))
ort = cast(Any, globals().get("ort", None))

# ---------- Constants ----------
DEFAULT_URLBERT_MODEL = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
DEFAULT_ONNX_MODEL_PATH = "./models/pirocheto_onnx/model.onnx"
DEFAULT_INFERENCE_TIMEOUT = 2.0
MAX_SEQUENCE_LENGTH = 128
SAFE_THRESHOLD = 30.0
PHISHING_THRESHOLD = 70.0
FALLBACK_SCORE = 50.0
FALLBACK_PROB = 0.5

# ---------- Enums ----------
class ModelHealthState(str, Enum):
    MODEL_READY = "MODEL_READY"
    MODEL_LOADING = "MODEL_LOADING"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_FALLBACK = "MODEL_FALLBACK"
    MODEL_ERROR = "MODEL_ERROR"

# ---------- Pydantic Models ----------
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

# ---------- Protocol ----------
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

# ---------- URLBERT Predictor ----------
class URLBERTPredictor:
    """
    Primary URL Classifier using URLBERT‑tiny.

    Lightweight BERT architecture optimized for URL tokens. Supports CPU/GPU
    with automatic fallback on import failure.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_URLBERT_MODEL,
        cache_dir: str = "./models",
        inference_timeout: float = DEFAULT_INFERENCE_TIMEOUT,
    ) -> None:
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
            logger.warning("Transformers/PyTorch not available for URLBERT.")
            self._loaded = False
            return False

        try:
            logger.info("🤖 Loading URLBERT model: %s on %s", self.model_name, self.device)

            def _load():
                tokenizer_cls = cast(Any, AutoTokenizer)
                model_cls = cast(Any, AutoModelForSequenceClassification)
                tokenizer = tokenizer_cls.from_pretrained(
                    self.model_name,
                    cache_dir=self.cache_dir,
                    trust_remote_code=False,
                )
                model = model_cls.from_pretrained(
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
        start = time.perf_counter()
        cleaned = URLPreprocessor.preprocess(url)

        if not cleaned:
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
                elapsed = (time.perf_counter() - start) * 1000.0
                return URLPredictionResult(
                    score=FALLBACK_SCORE,
                    phishing_probability=FALLBACK_PROB,
                    label="unknown",
                    model_id=self.model_name,
                    confidence=FALLBACK_PROB,
                    latency_ms=round(elapsed, 2),
                    fallback_used=True,
                    error="Model not loaded",
                )

        try:
            def _inference():
                inputs = self.tokenizer(
                    cleaned,
                    return_tensors="pt",
                    truncation=True,
                    max_length=MAX_SEQUENCE_LENGTH,
                    padding=True,
                )
                if hasattr(inputs, "items"):
                    inputs = {
                        k: (v.to(self.device) if hasattr(v, "to") else v)
                        for k, v in inputs.items()
                    }
                torch_local = cast(Any, torch)
                with torch_local.no_grad():
                    outputs = self.model(**inputs)
                    logits = outputs.logits
                    probs = torch_local.softmax(logits, dim=-1)
                return probs.cpu().numpy()[0]

            probs = await asyncio.wait_for(
                asyncio.to_thread(_inference),
                timeout=self.inference_timeout
            )
            phishing_prob = float(probs[1]) if len(probs) == 2 else float(max(probs))
            score = round(phishing_prob * 100.0, 2)

            if score < SAFE_THRESHOLD:
                label = "safe"
                conf = 1.0 - (score / 100.0)
            elif score < PHISHING_THRESHOLD:
                label = "suspicious"
                conf = 0.70
            else:
                label = "phishing"
                conf = score / 100.0

            elapsed = (time.perf_counter() - start) * 1000.0
            return URLPredictionResult(
                score=score,
                phishing_probability=round(phishing_prob, 4),
                label=label,
                model_id=self.model_name,
                confidence=round(conf, 2),
                latency_ms=round(elapsed, 2),
                fallback_used=False,
            )

        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000.0
            logger.warning("⏱️ URLBERT inference timeout after %ss", self.inference_timeout)
            return URLPredictionResult(
                score=FALLBACK_SCORE,
                phishing_probability=FALLBACK_PROB,
                label="unknown",
                model_id=self.model_name,
                confidence=FALLBACK_PROB,
                latency_ms=round(elapsed, 2),
                fallback_used=True,
                error="Timeout",
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000.0
            logger.error("❌ URLBERT inference error: %s", e, exc_info=True)
            return URLPredictionResult(
                score=FALLBACK_SCORE,
                phishing_probability=FALLBACK_PROB,
                label="unknown",
                model_id=self.model_name,
                confidence=FALLBACK_PROB,
                latency_ms=round(elapsed, 2),
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


# ---------- ONNX Predictor ----------
class ONNXURLPredictor:
    """
    Baseline URL Classifier using pirocheto/phishing‑url‑detection in ONNX format.

    LinearSVM with string n‑gram features for sub‑millisecond CPU inference.
    """

    def __init__(
        self,
        model_path: str = DEFAULT_ONNX_MODEL_PATH,
        model_name: str = "pirocheto/phishing-url-detection",
        inference_timeout: float = 1.0,
    ) -> None:
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
                ort_local = cast(Any, ort)
                return ort_local.InferenceSession(self.model_path, providers=["CPUExecutionProvider"])

            self.session = await asyncio.to_thread(_load)
            self._loaded = True
            logger.info("✅ ONNX URL model loaded from %s", self.model_path)
            return True
        except Exception as e:
            logger.error("❌ Failed to load ONNX model: %s", e)
            self._loaded = False
            return False

    async def predict(self, url: str) -> URLPredictionResult:
        start = time.perf_counter()
        cleaned = URLPreprocessor.preprocess(url)

        if not cleaned:
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
                elapsed = (time.perf_counter() - start) * 1000.0
                return URLPredictionResult(
                    score=FALLBACK_SCORE,
                    phishing_probability=FALLBACK_PROB,
                    label="unknown",
                    model_id=self.model_name,
                    confidence=FALLBACK_PROB,
                    latency_ms=round(elapsed, 2),
                    fallback_used=True,
                    error="ONNX model not loaded",
                )

        try:
            def _inference():
                inputs = np.array([cleaned], dtype=object)
                session_local = cast(Any, self.session)
                input_name = session_local.get_inputs()[0].name
                outputs = session_local.run(None, {input_name: inputs})
                # Output[1] contains list of dict probabilities [{0: prob_safe, 1: prob_phish}]
                if len(outputs) > 1 and len(outputs[1]) > 0:
                    prob_dict = outputs[1][0]
                    return float(prob_dict.get(1, FALLBACK_PROB))
                return FALLBACK_PROB

            phishing_prob = await asyncio.wait_for(
                asyncio.to_thread(_inference),
                timeout=self.inference_timeout
            )
            score = round(phishing_prob * 100.0, 2)

            if score < SAFE_THRESHOLD:
                label = "safe"
            elif score < PHISHING_THRESHOLD:
                label = "suspicious"
            else:
                label = "phishing"

            elapsed = (time.perf_counter() - start) * 1000.0
            return URLPredictionResult(
                score=score,
                phishing_probability=round(phishing_prob, 4),
                label=label,
                model_id=self.model_name,
                confidence=0.90,
                latency_ms=round(elapsed, 2),
                fallback_used=False,
            )

        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000.0
            logger.warning("⏱️ ONNX inference timeout after %ss", self.inference_timeout)
            return URLPredictionResult(
                score=FALLBACK_SCORE,
                phishing_probability=FALLBACK_PROB,
                label="unknown",
                model_id=self.model_name,
                confidence=FALLBACK_PROB,
                latency_ms=round(elapsed, 2),
                fallback_used=True,
                error="Timeout",
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000.0
            logger.error("❌ ONNX inference error: %s", e)
            return URLPredictionResult(
                score=FALLBACK_SCORE,
                phishing_probability=FALLBACK_PROB,
                label="unknown",
                model_id=self.model_name,
                confidence=FALLBACK_PROB,
                latency_ms=round(elapsed, 2),
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


# ---------- Mock Predictor ----------
class MockURLPredictor:
    """Deterministic Mock URL Predictor for testing and development."""

    def __init__(self, model_id: str = "mock-url-predictor") -> None:
        self.model_id = model_id
        self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded

    def get_health_state(self) -> ModelHealthState:
        return ModelHealthState.MODEL_READY if self._loaded else ModelHealthState.MODEL_UNAVAILABLE

    async def predict(self, url: str) -> URLPredictionResult:
        start = time.perf_counter()
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
        if "phish" in lowered or "malicious" in lowered or "paypa1" in lowered or "account-verify" in lowered:
            prob = 0.92
            label = "phishing"
            conf = 0.95
        elif "suspicious" in lowered or "warning" in lowered:
            prob = 0.55
            label = "suspicious"
            conf = 0.70
        else:
            prob = 0.05
            label = "safe"
            conf = 0.98

        elapsed = (time.perf_counter() - start) * 1000.0
        return URLPredictionResult(
            score=round(prob * 100.0, 2),
            phishing_probability=prob,
            label=label,
            model_id=self.model_id,
            confidence=conf,
            latency_ms=round(elapsed, 2),
            fallback_used=False,
        )


# ---------- Global Singletons ----------
_urlbert_instance: Optional[URLBERTPredictor] = None
_onnx_url_instance: Optional[ONNXURLPredictor] = None


async def get_urlbert_predictor() -> URLBERTPredictor:
    """Get or create the global URLBERT predictor instance (loaded lazily)."""
    global _urlbert_instance
    if _urlbert_instance is None:
        model_name = os.getenv("URLBERT_MODEL_NAME", DEFAULT_URLBERT_MODEL)
        cache_dir = os.getenv("HF_MODEL_CACHE_DIR", "./models")
        _urlbert_instance = URLBERTPredictor(model_name=model_name, cache_dir=cache_dir)
        await _urlbert_instance.load_model()
    return _urlbert_instance


async def get_onnx_url_predictor() -> ONNXURLPredictor:
    """Get or create the global ONNX predictor instance (loaded lazily)."""
    global _onnx_url_instance
    if _onnx_url_instance is None:
        model_path = os.getenv("ONNX_URL_MODEL_PATH", DEFAULT_ONNX_MODEL_PATH)
        _onnx_url_instance = ONNXURLPredictor(model_path=model_path)
        await _onnx_url_instance.load_model()
    return _onnx_url_instance