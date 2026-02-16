"""
Tier 2 ML Model Integration
Hugging Face DistilBERT model for phishing email detection
"""

import asyncio
import logging
import os
from typing import Optional, Tuple

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = logging.getLogger(__name__)


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
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._loaded = False

    async def load_model(self) -> bool:
        """Load the model and tokenizer asynchronously."""
        if self._loaded:
            return True

        try:
            logger.info(f"🤖 Loading ML model: {self.model_name}")
            logger.info(f"📁 Cache directory: {self.cache_dir}")
            logger.info(f"🖥️  Device: {self.device}")

            # Load in thread to avoid blocking
            def _load():
                tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, cache_dir=self.cache_dir
                )
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, cache_dir=self.cache_dir
                )
                model.to(self.device)
                model.eval()  # Set to evaluation mode
                return tokenizer, model

            self.tokenizer, self.model = await asyncio.to_thread(_load)
            self._loaded = True

            logger.info("✅ ML model loaded successfully")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to load ML model: {e}", exc_info=True)
            self._loaded = False
            return False

    async def predict(self, email_body: str) -> Tuple[float, str]:
        """
        Predict phishing probability for email body.

        Args:
            email_body: Email content to analyze

        Returns:
            Tuple of (phishing_score, confidence_label)
            - phishing_score: 0-100 (higher = more likely phishing)
            - confidence_label: "safe", "suspicious", or "phishing"
        """
        if not self._loaded:
            logger.warning("⚠️ Model not loaded, attempting to load now")
            loaded = await self.load_model()
            if not loaded:
                return 50.0, "unknown"  # Neutral score on failure

        try:
            # Truncate very long emails
            email_body = email_body[:512]

            # Run inference in thread
            def _inference():
                inputs = self.tokenizer(
                    email_body,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True,
                )
                inputs = {k: v.to(self.device) for k, v in inputs.items()}

                with torch.no_grad():
                    outputs = self.model(**inputs)
                    logits = outputs.logits
                    probabilities = torch.softmax(logits, dim=-1)

                return probabilities.cpu().numpy()[0]

            # Run with timeout
            probs = await asyncio.wait_for(
                asyncio.to_thread(_inference), timeout=self.inference_timeout
            )

            # Assuming binary classification: [safe, phishing]
            # Adjust based on actual model output
            if len(probs) == 2:
                phishing_prob = float(probs[1])  # Probability of phishing class
            else:
                # Multi-class: take max probability
                phishing_prob = float(max(probs))

            # Convert to 0-100 score
            phishing_score = phishing_prob * 100

            # Determine confidence label
            if phishing_score < 30:
                confidence = "safe"
            elif phishing_score < 70:
                confidence = "suspicious"
            else:
                confidence = "phishing"

            logger.debug(
                f"ML Prediction: score={phishing_score:.2f}, confidence={confidence}"
            )

            return phishing_score, confidence

        except asyncio.TimeoutError:
            logger.warning(f"⏱️ ML inference timeout after {self.inference_timeout}s")
            return 50.0, "timeout"
        except Exception as e:
            logger.error(f"❌ ML inference error: {e}", exc_info=True)
            return 50.0, "error"

    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return self._loaded

    async def unload_model(self):
        """Unload model from memory."""
        if self._loaded:
            self.model = None
            self.tokenizer = None
            self._loaded = False
            # Force garbage collection
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            logger.info("🗑️ ML model unloaded from memory")


# Global model instance (singleton pattern)
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

        # Load model on first access
        await _ml_model_instance.load_model()

    return _ml_model_instance
