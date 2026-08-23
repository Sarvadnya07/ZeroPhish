"""
Tier 2 ML Model Integration.
Hugging Face DistilBERT model for phishing email detection.
Safely handles optional torch/transformers dependencies.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional, Tuple

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


class PhishingMLModel:
    """
    ML-based phishing detection using DistilBERT.
    Model: cybersectony/phishing-email-detection-distilbert_v2.1
    """

    def __init__(
        self,
        model_name: str = "cybersectony/phishing-email-detection-distilbert_v2.1",
        cache_dir: str = "./models",
        inference_timeout: int = 2,
    ):
        self.model_name = model_name
        self.cache_dir = cache_dir
        self.inference_timeout = inference_timeout
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if (torch and hasattr(torch, "cuda") and torch.cuda.is_available()) else "cpu"
        self._loaded = False

    async def load_model(self) -> bool:
        """Load the model and tokenizer asynchronously."""
        if self._loaded:
            return True

        if not TRANSFORMERS_AVAILABLE or not torch or not AutoTokenizer:
            logger.warning("Transformers / Torch libraries are not installed. ML model unavailable.")
            self._loaded = False
            return False

        try:
            logger.info("🤖 Loading ML model: %s", self.model_name)
            logger.info("📁 Cache directory: %s", self.cache_dir)
            logger.info("🖥️  Device: %s", self.device)

            def _load():
                tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, cache_dir=self.cache_dir
                )
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, cache_dir=self.cache_dir
                )
                if hasattr(model, "to"):
                    model.to(self.device)
                if hasattr(model, "eval"):
                    model.eval()
                return tokenizer, model

            self.tokenizer, self.model = await asyncio.to_thread(_load)
            self._loaded = True
            logger.info("✅ ML model loaded successfully")
            return True

        except Exception as e:
            logger.error("❌ Failed to load ML model: %s", e, exc_info=True)
            self._loaded = False
            return False

    async def predict(self, email_body: str) -> Tuple[float, str]:
        """
        Predict phishing probability for email body.
        Returns: (phishing_score 0-100, confidence_label "safe" | "suspicious" | "phishing")
        """
        if not self._loaded:
            loaded = await self.load_model()
            if not loaded:
                return 50.0, "unknown"

        try:
            email_body = email_body[:512]

            def _inference():
                inputs = self.tokenizer(
                    email_body,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True,
                )
                if hasattr(inputs, "items"):
                    inputs = {k: (v.to(self.device) if hasattr(v, "to") else v) for k, v in inputs.items()}

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

            if len(probs) == 2:
                phishing_prob = float(probs[1])
            else:
                phishing_prob = float(max(probs))

            phishing_score = phishing_prob * 100

            if phishing_score < 30:
                confidence = "safe"
            elif phishing_score < 70:
                confidence = "suspicious"
            else:
                confidence = "phishing"

            return phishing_score, confidence

        except asyncio.TimeoutError:
            logger.warning("⏱️ ML inference timeout after %ss", self.inference_timeout)
            return 50.0, "timeout"
        except Exception as e:
            logger.error("❌ ML inference error: %s", e, exc_info=True)
            return 50.0, "error"

    def is_loaded(self) -> bool:
        return self._loaded

    async def unload_model(self):
        """Unload model from memory."""
        if self._loaded:
            self.model = None
            self.tokenizer = None
            self._loaded = False
            if torch and hasattr(torch, "cuda") and torch.cuda.is_available():
                torch.cuda.empty_cache()
            logger.info("🗑️ ML model unloaded from memory")


_ml_model_instance: Optional[PhishingMLModel] = None


async def get_ml_model() -> PhishingMLModel:
    """Get or create the global ML model instance."""
    global _ml_model_instance

    if _ml_model_instance is None:
        model_name = os.getenv(
            "HF_MODEL_NAME", "cybersectony/phishing-email-detection-distilbert_v2.1"
        )
        cache_dir = os.getenv("HF_MODEL_CACHE_DIR", "./models")
        timeout = int(os.getenv("ML_INFERENCE_TIMEOUT", "2"))

        _ml_model_instance = PhishingMLModel(
            model_name=model_name, cache_dir=cache_dir, inference_timeout=timeout
        )
        await _ml_model_instance.load_model()

    return _ml_model_instance
