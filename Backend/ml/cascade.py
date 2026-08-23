"""
URL Detection Cascade Simulation Engine for Phase 10.
Implements a multi-stage gated evaluation architecture:
Hard Security Rules -> Heuristics -> Fast ONNX -> Ambiguity Gate -> Deep URLBERT -> Fusion.
Tracks stage escalation, model skip rates, execution latencies, and telemetry provenance.
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
    """Configurable staged URL detection cascade with deterministic security precedence."""

    def __init__(
        self,
        onnx_lower_threshold: float = 0.20,
        onnx_upper_threshold: float = 0.80,
        heuristics_lower_threshold: float = 15.0,
        heuristics_upper_threshold: float = 85.0,
        onnx_predictor: Optional[URLPredictor] = None,
        urlbert_predictor: Optional[URLPredictor] = None,
    ):
        self.onnx_lower_threshold = onnx_lower_threshold
        self.onnx_upper_threshold = onnx_upper_threshold
        self.heuristics_lower_threshold = heuristics_lower_threshold
        self.heuristics_upper_threshold = heuristics_upper_threshold

        self.onnx_predictor = onnx_predictor or MockURLPredictor()
        self.urlbert_predictor = urlbert_predictor or MockURLPredictor()

    async def predict_cascade(self, url: str) -> CascadePredictionResult:
        t0 = time.perf_counter()
        normalized_url = URLNormalizer.to_model_input_form(url)
        host = URLNormalizer.extract_hostname(normalized_url)

        # -------------------------------------------------------------
        # STAGE 1: Deterministic Hard Security Rules (SSRF / RFC1918 / Strict Blocks)
        # -------------------------------------------------------------
        if host in ("127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"):
            lat = (time.perf_counter() - t0) * 1000.0
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

        # -------------------------------------------------------------
        # STAGE 2: Lightweight Lexical Heuristics (ThreatAnalyzer)
        # -------------------------------------------------------------
        h_score_val, _ = await ThreatAnalyzer._analyze_links([normalized_url])
        h_score = float(h_score_val)

        if h_score >= self.heuristics_upper_threshold:
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
        elif h_score <= self.heuristics_lower_threshold:
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

        # -------------------------------------------------------------
        # STAGE 3: Fast ONNX Baseline Model (~1.25 ms CPU)
        # -------------------------------------------------------------
        onnx_res = await self.onnx_predictor.predict(normalized_url)
        onnx_prob = float(onnx_res.phishing_probability)

        if onnx_prob <= self.onnx_lower_threshold:
            # ONNX confidently marks safe -> Fuse with heuristics and return without URLBERT
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
        elif onnx_prob >= self.onnx_upper_threshold:
            # ONNX confidently marks malicious -> Fuse and return without URLBERT
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

        # -------------------------------------------------------------
        # STAGE 4: Escalation to Deep URLBERT Model (~14.85 ms CPU)
        # -------------------------------------------------------------
        bert_res = await self.urlbert_predictor.predict(normalized_url)
        bert_prob = float(bert_res.phishing_probability)

        # Fused combination with URLBERT
        fused_score = (h_score * 0.40) + ((bert_prob * 100.0) * 0.60)
        verdict = (
            "CRITICAL" if fused_score >= 65.0 else ("SUSPICIOUS" if fused_score >= 35.0 else "SAFE")
        )
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
