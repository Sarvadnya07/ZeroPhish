"""
Tier 2 ML Model Integration.

Hugging Face DistilBERT model for phishing email detection.
Safely handles optional torch/transformers dependencies with graceful fallback.

Environment variables:
- ML_ENABLED: "true" or "false" (default "true")
- ZERO_PHISH_DISABLE_ML: "1" or "0" (default "0")
- HF_MODEL_NAME: model ID (default: cybersectony/phishing-email-detection-distilbert_v2.1)
- HF_MODEL_CACHE_DIR: cache directory (default: ./models)
- ML_INFERENCE_TIMEOUT: inference timeout in seconds (default: 2)
- ML_DEVICE: "cuda" or "cpu" (auto-detected by default)
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.machinery
import logging
import os
import sys
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

# ---------- Platform workarounds ----------
def _ensure_stub_module(name: str, *, is_package: bool = False):
    """Create a module stub with a valid __spec__ so importlib.find_spec() does not crash."""
    import types

    module = sys.modules.setdefault(name, types.ModuleType(name))
    if getattr(module, "__spec__", None) is None:
        module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, is_package=is_package)
        if is_package:
            module.__path__ = []
    return module


if sys.platform == "win32":
    # Prevent transformers from loading broken torchvision C-extension DLLs on Windows Python 3.13
    # Insert dummy modules instead of None to satisfy type checkers expecting a module object
    _ensure_stub_module("torchvision", is_package=True)
    _ensure_stub_module("torchvision.transforms")

# ---------- Optional imports ----------
try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    TRANSFORMERS_AVAILABLE = True
except (ImportError, OSError, RuntimeError, Exception) as _import_err:
    logger.debug("Torch/Transformers unavailable or failed import: %s", _import_err)
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    TRANSFORMERS_AVAILABLE = False

# ---------- Configuration ----------
DEFAULT_MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.1"
DEFAULT_CACHE_DIR = "./models"
DEFAULT_INFERENCE_TIMEOUT = 2
DEFAULT_MAX_SEQUENCE_LENGTH = 512
ML_ENABLED = os.getenv("ML_ENABLED", "true").lower() == "true"
ML_DISABLED = os.getenv("ZERO_PHISH_DISABLE_ML", "0").lower() in ("1", "true")
INFERENCE_TIMEOUT = int(os.getenv("ML_INFERENCE_TIMEOUT", str(DEFAULT_INFERENCE_TIMEOUT)))
MAX_SEQ_LEN = int(os.getenv("ML_MAX_SEQUENCE_LENGTH", str(DEFAULT_MAX_SEQUENCE_LENGTH)))
MODEL_NAME = os.getenv("HF_MODEL_NAME", DEFAULT_MODEL_NAME)
CACHE_DIR = os.getenv("HF_MODEL_CACHE_DIR", DEFAULT_CACHE_DIR)
FORCE_CPU = os.getenv("ML_DEVICE", "").lower() == "cpu"

# Determine device
if FORCE_CPU:
    DEVICE = "cpu"
elif torch is not None and hasattr(torch, "cuda") and torch.cuda.is_available():
    DEVICE = "cuda"
else:
    DEVICE = "cpu"


class PhishingMLModel:
    """
    ML‑based phishing detection using DistilBERT.

    Model: cybersectony/phishing-email-detection-distilbert_v2.1

    Attributes:
        model_name: Hugging Face model ID.
        cache_dir: Directory for caching the model.
        inference_timeout: Maximum time for inference in seconds.
        device: "cuda" or "cpu".
        model: Loaded model (None if not loaded).
        tokenizer: Loaded tokenizer (None if not loaded).
        _loaded: Boolean indicating if the model is loaded.
        _health: Health status dictionary.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
        cache_dir: str = DEFAULT_CACHE_DIR,
        inference_timeout: int = DEFAULT_INFERENCE_TIMEOUT,
    ) -> None:
        self.model_name = model_name
        self.cache_dir = cache_dir
        self.inference_timeout = inference_timeout
        self.device = DEVICE
        self.model = None
        self.tokenizer = None
        self._loaded = False
        self._health = {"status": "uninitialized", "message": "Model not yet loaded"}

        # Check if ML is enabled
        if not ML_ENABLED or ML_DISABLED:
            self._health = {
                "status": "disabled",
                "message": "ML inference disabled by environment configuration.",
            }
            logger.info("ML inference disabled by environment.")
            return

        if not TRANSFORMERS_AVAILABLE or not torch or not AutoTokenizer:
            self._health = {
                "status": "unavailable",
                "message": "Transformers/Torch libraries not installed or failed to import.",
            }
            logger.warning("Transformers/Torch unavailable; ML model will not load.")
            return

        self._health = {"status": "ready_to_load", "message": "Model can be loaded on demand."}

    async def load_model(self) -> bool:
        """
        Load the model and tokenizer asynchronously.

        Returns:
            True if loaded successfully, False otherwise.
        """
        if self._loaded:
            return True

        if not ML_ENABLED or ML_DISABLED:
            self._health = {"status": "disabled", "message": "ML disabled by environment."}
            return False

        if not TRANSFORMERS_AVAILABLE or not torch or not AutoTokenizer:
            self._health = {
                "status": "unavailable",
                "message": "Transformers/Torch libraries not available.",
            }
            return False

        tokenizer_cls = AutoTokenizer
        model_cls = AutoModelForSequenceClassification
        if tokenizer_cls is None or model_cls is None:
            self._health = {
                "status": "unavailable",
                "message": "Tokenizer/model classes not available.",
            }
            return False

        try:
            logger.info("Loading ML model: %s on %s", self.model_name, self.device)
            logger.info("Cache directory: %s", self.cache_dir)

            def _load():
                tokenizer = tokenizer_cls.from_pretrained(self.model_name, cache_dir=self.cache_dir)
                model = model_cls.from_pretrained(self.model_name, cache_dir=self.cache_dir)
                if hasattr(model, "to"):
                    model.to(self.device)
                if hasattr(model, "eval"):
                    model.eval()
                return tokenizer, model

            self.tokenizer, self.model = await asyncio.to_thread(_load)
            self._loaded = True
            self._health = {"status": "healthy", "message": "Model loaded successfully."}
            logger.info("ML model loaded successfully.")
            return True

        except Exception as e:
            self._loaded = False
            self._health = {"status": "error", "message": f"Loading failed: {type(e).__name__}"}
            logger.error("Failed to load ML model: %s", e, exc_info=True)
            return False

    async def predict(self, email_body: str) -> Tuple[float, str]:
        """
        Predict phishing probability for email body.

        Args:
            email_body: Email text to analyze.

        Returns:
            Tuple of (phishing_score 0‑100, confidence_label)
            - confidence_label: "safe" | "suspicious" | "phishing" | "unknown" | "timeout" | "error"
        """
        if not self._loaded:
            loaded = await self.load_model()
            if not loaded:
                logger.warning("Model not loaded; returning fallback prediction.")
                return 50.0, "unavailable"

        # Sanitise and truncate input
        if not email_body or not email_body.strip():
            return 0.0, "safe"

        # Truncate to reasonable length
        if len(email_body) > MAX_SEQ_LEN * 2:
            email_body = email_body[:MAX_SEQ_LEN * 2]  # Tokenizer will further truncate

        try:
            def _inference():
                # Ensure tokenizer is present and callable
                if self.tokenizer is None or not callable(self.tokenizer):
                    raise RuntimeError("Tokenizer not loaded or unavailable")

                inputs = self.tokenizer(
                    email_body,
                    return_tensors="pt",
                    truncation=True,
                    max_length=MAX_SEQ_LEN,
                    padding=True,
                )
                # Ensure inputs is a mapping before iterating; some tokenizers may
                # return specialized objects (e.g. BatchEncoding). Convert to a
                # plain dict and move tensors to the correct device.
                from collections.abc import Mapping

                if not isinstance(inputs, dict) and isinstance(inputs, Mapping):
                    inputs = dict(inputs)

                if isinstance(inputs, dict):
                    inputs = {
                        str(k): (v.to(self.device) if hasattr(v, "to") else v)
                        for k, v in inputs.items()
                    }
                else:
                    # If inputs is not a mapping at this point, fail early with
                    # a clear error rather than passing a non-mapping to **.
                    raise RuntimeError("Tokenizer returned non-mapping inputs for model call")

                # Use torch.no_grad() when available; fall back to a no-op context
                no_grad_ctx = getattr(torch, "no_grad", None)
                if no_grad_ctx is None:
                    no_grad_ctx = contextlib.nullcontext

                if self.model is None:
                    raise RuntimeError("Model not loaded")

                with no_grad_ctx():
                    # self.model should be a callable nn.Module; ensure inputs is a
                    # mapping with string keys (done above) before expanding.
                    outputs = self.model(**inputs)
                    # Extract logits from various possible model output types
                    logits = None
                    # HuggingFace-style ModelOutput or object with .logits
                    if hasattr(outputs, "logits"):
                        logits = outputs.logits
                    # Dict-like outputs
                    elif isinstance(outputs, dict):
                        logits = outputs.get("logits")
                    # Tuple outputs (e.g., (logits, ...))
                    elif isinstance(outputs, (list, tuple)) and len(outputs) > 0:
                        logits = outputs[0]
                    # Direct tensor output (guard against torch being None or missing is_tensor)
                    else:
                        # Guard against torch being None or is_tensor missing
                        is_tensor_fn = getattr(torch, "is_tensor", None)
                        if callable(is_tensor_fn) and is_tensor_fn(outputs):
                            logits = outputs

                    if logits is None:
                        raise RuntimeError("Model did not return logits for softmax")

                    # Prefer torch softmax when available; fall back to numpy when torch is not present.
                    if torch is not None:
                        probabilities = torch.softmax(torch.as_tensor(logits), dim=-1)
                        probs_np = probabilities.cpu().numpy()[0]
                    else:
                        # Lightweight numpy softmax fallback for environments without torch
                        import numpy as _np

                        arr = _np.asarray(logits)
                        # numerically stable softmax along last axis
                        exps = _np.exp(arr - _np.max(arr, axis=-1, keepdims=True))
                        probs_np = (exps / _np.sum(exps, axis=-1, keepdims=True))[0]
                return probs_np

            probs = await asyncio.wait_for(
                asyncio.to_thread(_inference),
                timeout=self.inference_timeout,
            )

            if len(probs) == 2:
                phishing_prob = float(probs[1])
            else:
                phishing_prob = float(max(probs))

            phishing_score = phishing_prob * 100.0

            if phishing_score < 30:
                confidence = "safe"
            elif phishing_score < 70:
                confidence = "suspicious"
            else:
                confidence = "phishing"

            logger.debug("ML prediction: score=%.1f, confidence=%s", phishing_score, confidence)
            return phishing_score, confidence

        except asyncio.TimeoutError:
            logger.warning("ML inference timed out after %ds", self.inference_timeout)
            return 50.0, "timeout"
        except Exception as e:
            logger.error("ML inference error: %s", e, exc_info=True)
            return 50.0, "error"

    def is_loaded(self) -> bool:
        """Return True if the model is loaded and ready for inference."""
        return self._loaded and self.model is not None and self.tokenizer is not None

    async def unload_model(self) -> None:
        """Unload model from memory to free resources."""
        if self._loaded:
            self.model = None
            self.tokenizer = None
            self._loaded = False
            # Clear CUDA cache if available
            if torch is not None and hasattr(torch, "cuda") and torch.cuda.is_available():
                torch.cuda.empty_cache()
            self._health = {"status": "unloaded", "message": "Model unloaded from memory."}
            logger.info("ML model unloaded.")

    def get_health(self) -> Dict[str, Any]:
        """
        Return health status of the ML model.

        Returns:
            Dict with keys: status, message, and additional details.
        """
        if self._loaded:
            return {
                "status": "healthy",
                "message": "Model loaded and ready.",
                "device": self.device,
                "model_name": self.model_name,
                "cache_dir": self.cache_dir,
            }
        return self._health

    async def health_check(self) -> Dict[str, Any]:
        """
        Comprehensive health check including a lightweight inference test.

        Returns:
            Dict with detailed health status.
        """
        status = self.get_health()
        status["is_loaded"] = self.is_loaded()
        status["transformers_available"] = TRANSFORMERS_AVAILABLE
        status["torch_available"] = torch is not None

        # Test inference with a short sample
        if self.is_loaded():
            try:
                test_score, test_conf = await self.predict("This is a test email.")
                status["test_inference_success"] = True
                status["test_inference_score"] = round(test_score, 1)
                status["test_inference_confidence"] = test_conf
            except Exception as e:
                status["test_inference_success"] = False
                status["test_inference_error"] = str(e)
        else:
            status["test_inference_success"] = None

        return status


# ---------- Global Instance ----------
_ml_model_instance: Optional[PhishingMLModel] = None


async def get_ml_model() -> PhishingMLModel:
    """Get or create the global ML model instance (lazy-loaded)."""
    global _ml_model_instance

    if _ml_model_instance is None:
        _ml_model_instance = PhishingMLModel(
            model_name=os.getenv("HF_MODEL_NAME", DEFAULT_MODEL_NAME),
            cache_dir=os.getenv("HF_MODEL_CACHE_DIR", DEFAULT_CACHE_DIR),
            inference_timeout=int(os.getenv("ML_INFERENCE_TIMEOUT", str(DEFAULT_INFERENCE_TIMEOUT))),
        )
        await _ml_model_instance.load_model()

    return _ml_model_instance