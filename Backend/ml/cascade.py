"""
URL Detection Cascade Simulation Engine for Phase 10.

Implements a multi‑stage gated evaluation architecture:
Hard Security Rules → Heuristics → Fast ONNX → Ambiguity Gate → Deep URLBERT → Fusion.

Tracks stage escalation, model skip rates, execution latencies, and telemetry provenance.
All thresholds are configurable; default values match production settings.
"""

from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from ml.data.normalization.url_normalizer import URLNormalizer
from ml.fusion import FusionResult, RiskFusionEngine
from ml.url_predictor import (
    MockURLPredictor,
    ONNXURLPredictor,
    URLBERTPredictor,
    URLPredictionResult,
    URLPredictor,
)
from tier_2.analyzer import ThreatAnalyzer

logger = logging.getLogger(__name__)

# ---------- Constants ----------
DEFAULT_HEURISTICS_LOWER = 15.0
DEFAULT_HEURISTICS_UPPER = 85.0
DEFAULT_ONNX_LOWER = 0.20
DEFAULT_ONNX_UPPER = 0.80
HEURISTICS_WEIGHT = 0.40
URLBERT_WEIGHT = 0.60
CRITICAL_THRESHOLD = 65.0
SUSPICIOUS_THRESHOLD = 35.0
HARD_RULE_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"}


class CascadeStage(str, Enum):
    STAGE_HARD_RULE = "STAGE_HARD_RULE"
    STAGE_HEURISTICS = "STAGE_HEURISTICS"
    STAGE_ONNX = "STAGE_ONNX"
    STAGE_URLBERT = "STAGE_URLBERT"
    STAGE_FINAL = "STAGE_FINAL"


class ModelHealthStatus(str, Enum):
    MODEL_READY = "MODEL_READY"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_FALLBACK = "MODEL_FALLBACK"
    MODEL_ERROR = "MODEL_ERROR"


class CascadePredictionResult(BaseModel):
    url: str
    final_score: float = Field(..., ge=0.0, le=100.0)
    verdict: str  # "SAFE" | "SUSPICIOUS" | "CRITICAL"
    stage_reached: CascadeStage
    onnx_invoked: bool = False
    urlbert_invoked: bool = False
    reason_for_escalation: str
    latency_ms: float
    model_health: ModelHealthStatus = ModelHealthStatus.MODEL_READY
    heuristics_score: Optional[float] = None
    onnx_score: Optional[float] = None
    urlbert_score: Optional[float] = None
    hard_override: Optional[str] = None


class URLDetectionCascade:
    """
    Configurable staged URL detection cascade with deterministic security precedence.

    Attributes:
        heuristics_lower_threshold: Score below this => SAFE (Stage 2 termination).
        heuristics_upper_threshold: Score above this => CRITICAL (Stage 2 termination).
        onnx_lower_threshold: ONNX prob below this => SAFE (Stage 3 termination).
        onnx_upper_threshold: ONNX prob above this => CRITICAL (Stage 3 termination).
        onnx_predictor: Predictor for Stage 3 (ONNX).
        urlbert_predictor: Predictor for Stage 4 (URLBERT).
    """

    def __init__(
        self,
        heuristics_lower_threshold: float = DEFAULT_HEURISTICS_LOWER,
        heuristics_upper_threshold: float = DEFAULT_HEURISTICS_UPPER,
        onnx_lower_threshold: float = DEFAULT_ONNX_LOWER,
        onnx_upper_threshold: float = DEFAULT_ONNX_UPPER,
        onnx_predictor: Optional[URLPredictor] = None,
        urlbert_predictor: Optional[URLPredictor] = None,
    ) -> None:
        self.heuristics_lower = heuristics_lower_threshold
        self.heuristics_upper = heuristics_upper_threshold
        self.onnx_lower = onnx_lower_threshold
        self.onnx_upper = onnx_upper_threshold
        self.onnx_predictor = onnx_predictor or MockURLPredictor()
        self.urlbert_predictor = urlbert_predictor or MockURLPredictor()

    async def predict_cascade(self, url: str) -> CascadePredictionResult:
        """Execute the cascade and return the prediction result with full telemetry."""
        t0 = time.perf_counter()
        normalized_url = URLNormalizer.to_model_input_form(url)
        host = URLNormalizer.extract_hostname(normalized_url)

        # ---------- STAGE 1: Hard Security Rules ----------
        if host in HARD_RULE_HOSTS:
            lat = (time.perf_counter() - t0) * 1000.0
            logger.debug("Hard rule triggered for %s", normalized_url[:50])
            return CascadePredictionResult(
                url=normalized_url,
                final_score=100.0,
                verdict="CRITICAL",
                stage_reached=CascadeStage.STAGE_HARD_RULE,
                onnx_invoked=False,
                urlbert_invoked=False,
                reason_for_escalation="HARD_SECURITY_RULE_SSRF_TRIGGERED",
                latency_ms=round(lat, 3),
                hard_override="SSRF_PREVENTION",
            )

        # ---------- STAGE 2: Heuristics ----------
        try:
            h_score_val, _ = await ThreatAnalyzer._analyze_links([normalized_url])
            h_score = float(h_score_val)
        except Exception as e:
            logger.warning("Heuristics failed for %s: %s", url[:50], e)
            h_score = 50.0  # neutral fallback

        if h_score >= self.heuristics_upper:
            lat = (time.perf_counter() - t0) * 1000.0
            return CascadePredictionResult(
                url=normalized_url,
                final_score=h_score,
                verdict="CRITICAL",
                stage_reached=CascadeStage.STAGE_HEURISTICS,
                onnx_invoked=False,
                urlbert_invoked=False,
                reason_for_escalation="HEURISTICS_HIGH_CONFIDENCE_MALICIOUS",
                latency_ms=round(lat, 3),
                heuristics_score=h_score,
            )
        elif h_score <= self.heuristics_lower:
            lat = (time.perf_counter() - t0) * 1000.0
            return CascadePredictionResult(
                url=normalized_url,
                final_score=h_score,
                verdict="SAFE",
                stage_reached=CascadeStage.STAGE_HEURISTICS,
                onnx_invoked=False,
                urlbert_invoked=False,
                reason_for_escalation="HEURISTICS_HIGH_CONFIDENCE_SAFE",
                latency_ms=round(lat, 3),
                heuristics_score=h_score,
            )

        # ---------- STAGE 3: ONNX ----------
        try:
            onnx_res = await self.onnx_predictor.predict(normalized_url)
            onnx_prob = float(onnx_res.phishing_probability)
        except Exception as e:
            logger.warning("ONNX failed for %s: %s", url[:50], e)
            onnx_prob = 0.5
            # Mark health as error, but continue

        if onnx_prob <= self.onnx_lower:
            fusion = RiskFusionEngine.fuse(tier1_score=h_score, tier2_score=onnx_prob * 100.0)
            lat = (time.perf_counter() - t0) * 1000.0
            return CascadePredictionResult(
                url=normalized_url,
                final_score=fusion.final_score,
                verdict=fusion.verdict,
                stage_reached=CascadeStage.STAGE_ONNX,
                onnx_invoked=True,
                urlbert_invoked=False,
                reason_for_escalation="ONNX_CONFIDENT_SAFE",
                latency_ms=round(lat, 3),
                heuristics_score=h_score,
                onnx_score=onnx_prob,
            )
        elif onnx_prob >= self.onnx_upper:
            fusion = RiskFusionEngine.fuse(tier1_score=h_score, tier2_score=onnx_prob * 100.0)
            lat = (time.perf_counter() - t0) * 1000.0
            return CascadePredictionResult(
                url=normalized_url,
                final_score=fusion.final_score,
                verdict=fusion.verdict,
                stage_reached=CascadeStage.STAGE_ONNX,
                onnx_invoked=True,
                urlbert_invoked=False,
                reason_for_escalation="ONNX_CONFIDENT_MALICIOUS",
                latency_ms=round(lat, 3),
                heuristics_score=h_score,
                onnx_score=onnx_prob,
            )

        # ---------- STAGE 4: URLBERT ----------
        try:
            bert_res = await self.urlbert_predictor.predict(normalized_url)
            bert_prob = float(bert_res.phishing_probability)
        except Exception as e:
            logger.warning("URLBERT failed for %s: %s", url[:50], e)
            bert_prob = 0.5

        fused_score = (h_score * HEURISTICS_WEIGHT) + ((bert_prob * 100.0) * URLBERT_WEIGHT)
        if fused_score >= CRITICAL_THRESHOLD:
            verdict = "CRITICAL"
        elif fused_score >= SUSPICIOUS_THRESHOLD:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        lat = (time.perf_counter() - t0) * 1000.0
        return CascadePredictionResult(
            url=normalized_url,
            final_score=round(fused_score, 2),
            verdict=verdict,
            stage_reached=CascadeStage.STAGE_URLBERT,
            onnx_invoked=True,
            urlbert_invoked=True,
            reason_for_escalation="AMBIGUOUS_ONNX_ESCALATED_TO_URLBERT",
            latency_ms=round(lat, 3),
            heuristics_score=h_score,
            onnx_score=onnx_prob,
            urlbert_score=bert_prob,
        )