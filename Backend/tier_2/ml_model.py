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


class MetadataEnsemble:
    """
    Simulated lightweight ensemble model (e.g. CatBoost/XGBoost)
    that operates on email metadata rather than just the body text.
    """
    @staticmethod
    def predict(sender: str, links: list) -> float:
        score = 0.0
        domain = (sender or "").split("@")[-1].lower()
        
        # 1. Reputation Heuristics
        high_risk_tlds = [".top", ".xyz", ".click", ".win", ".link"]
        if any(domain.endswith(tld) for tld in high_risk_tlds):
            score += 40.0
            
        # 2. Link Density & Suspicion
        link_count = len(links)
        if link_count > 5:
            score += 15.0
        
        for link in links:
            if "xn--" in link: # Punycode
                score += 30.0
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", link): # IP-based
                score += 35.0
                
        return min(100.0, score)

class PhishingMLModel:
    """
    ML-based phishing detection using DistilBERT + Metadata Ensemble.
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
        self.metadata_ensemble = MetadataEnsemble()

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

    async def predict(self, email_body: str, sender: str = None, links: list = None) -> Tuple[float, str]:
        """
        Predict phishing probability using an ensemble of DistilBERT and Metadata analysis.

        Returns:
            Tuple of (phishing_score, confidence_label)
        """
        # 1. Primary Model: DistilBERT
        bert_score = 50.0
        if self._loaded:
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
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}
                    with torch.no_grad():
                        outputs = self.model(**inputs)
                        logits = outputs.logits
                        probabilities = torch.softmax(logits, dim=-1)
                    return probabilities.cpu().numpy()[0]

                probs = await asyncio.wait_for(
                    asyncio.to_thread(_inference), timeout=self.inference_timeout
                )
                bert_score = float(probs[1]) * 100 if len(probs) == 2 else float(max(probs)) * 100
            except Exception as e:
                logger.warning(f"DistilBERT inference failed: {e}")
        
        # 2. Secondary Model: Metadata Ensemble (Always available)
        metadata_score = self.metadata_ensemble.predict(sender, links or [])
        
        # 3. Ensemble Calculation (Weighted Average)
        # Weights: DistilBERT (70%), Metadata (30%)
        phishing_score = (bert_score * 0.7) + (metadata_score * 0.3)

        # Determine confidence label
        if phishing_score < 30:
            confidence = "safe"
        elif phishing_score < 70:
            confidence = "suspicious"
        else:
            confidence = "phishing"

        logger.debug(
            f"Ensemble Prediction: bert={bert_score:.1f}, meta={metadata_score:.1f}, final={phishing_score:.2f}"
        )

        return phishing_score, confidence

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
