"""
Controlled URL Cascade Shadow Mode Manager.

Manages asynchronous, non‑interfering shadow evaluation of the URL cascade
with configurable sampling, concurrency control, and telemetry recording.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from ml.cascade import CascadePredictionResult, CascadeStage, URLDetectionCascade
from ml.data.normalization.url_normalizer import URLNormalizer

logger = logging.getLogger(__name__)

# ---------- Enums ----------
class ShadowStatus(str, Enum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    DROPPED_CAPACITY = "DROPPED_CAPACITY"
    ERROR = "ERROR"
    SKIPPED_SAMPLING = "SKIPPED_SAMPLING"


class DisagreementCategory(str, Enum):
    NONE = "NONE"
    PRODUCTION_MALICIOUS_CASCADE_SAFE = "PRODUCTION_MALICIOUS_CASCADE_SAFE"
    PRODUCTION_SAFE_CASCADE_MALICIOUS = "PRODUCTION_SAFE_CASCADE_MALICIOUS"
    PRODUCTION_SUSPICIOUS_CASCADE_SAFE = "PRODUCTION_SUSPICIOUS_CASCADE_SAFE"
    PRODUCTION_SAFE_CASCADE_SUSPICIOUS = "PRODUCTION_SAFE_CASCADE_SUSPICIOUS"
    OTHER = "OTHER"


# ---------- Models ----------
class ShadowCascadeObservation(BaseModel):
    """Structured telemetry record for a shadow cascade observation."""
    observation_id: str
    timestamp: str
    url_sha256: str
    hostname_sha256: str
    production_verdict: str
    cascade_verdict: Optional[str] = None
    production_score: float
    cascade_score: Optional[float] = None
    stage_reached: Optional[str] = None
    heuristics_resolved: bool = False
    onnx_invoked: bool = False
    urlbert_invoked: bool = False
    model_health: str = "MODEL_READY"
    cascade_latency_ms: float = 0.0
    shadow_status: ShadowStatus
    disagreement: bool = False
    disagreement_category: DisagreementCategory = DisagreementCategory.NONE
    security_override_triggered: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ShadowConfig:
    """Configuration for the shadow manager."""
    enabled: bool = False
    sample_rate: float = 0.0
    timeout_ms: int = 2000
    max_concurrency: int = 10
    max_buffer_size: int = 1000

    @classmethod
    def from_env(cls) -> ShadowConfig:
        """Load configuration from environment variables."""
        enabled = os.getenv("ZEROPHISH_CASCADE_SHADOW_MODE", "false").lower() in ("1", "true", "yes")
        sample_rate = float(os.getenv("ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE", "0.0"))
        timeout_ms = int(os.getenv("CASCADE_SHADOW_TIMEOUT_MS", "2000"))
        max_concurrency = int(os.getenv("MAX_SHADOW_CASCADE_CONCURRENCY", "10"))
        return cls(
            enabled=enabled,
            sample_rate=sample_rate,
            timeout_ms=timeout_ms,
            max_concurrency=max_concurrency,
        )


class ShadowCascadeManager:
    """
    Manages asynchronous, non‑interfering shadow evaluation of the URL cascade.

    This is a singleton that records observations, aggregates metrics, and
    dispatches shadow tasks without blocking the main request path.
    """

    _instance: Optional[ShadowCascadeManager] = None

    def __init__(self, config: Optional[ShadowConfig] = None):
        if config is None:
            config = ShadowConfig.from_env()
        self.config = config

        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._cascade = URLDetectionCascade()
        self._observations: Deque[ShadowCascadeObservation] = deque(maxlen=config.max_buffer_size)

        # Operational counters
        self._metrics = {
            "observations_total": 0,
            "success_total": 0,
            "timeouts_total": 0,
            "dropped_capacity_total": 0,
            "errors_total": 0,
            "disagreements_total": 0,
            "potential_fn_total": 0,
            "urlbert_invocations_total": 0,
            "onnx_invocations_total": 0,
            "heuristics_resolved_total": 0,
            "hard_rules_resolved_total": 0,
        }
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls, config: Optional[ShadowConfig] = None) -> ShadowCascadeManager:
        if cls._instance is None:
            cls._instance = cls(config)
        return cls._instance

    @staticmethod
    def _hash_str(val: str) -> str:
        return hashlib.sha256(val.encode("utf-8")).hexdigest()

    async def _record_observation(self, obs: ShadowCascadeObservation) -> None:
        """Record an observation and update metrics (thread‑safe)."""
        async with self._lock:
            self._observations.append(obs)
            self._metrics["observations_total"] += 1
            if obs.shadow_status == ShadowStatus.SUCCESS:
                self._metrics["success_total"] += 1
                if obs.urlbert_invoked:
                    self._metrics["urlbert_invocations_total"] += 1
                if obs.onnx_invoked:
                    self._metrics["onnx_invocations_total"] += 1
                if obs.heuristics_resolved:
                    self._metrics["heuristics_resolved_total"] += 1
                if obs.stage_reached == CascadeStage.STAGE_HARD_RULE.value:
                    self._metrics["hard_rules_resolved_total"] += 1
                if obs.disagreement:
                    self._metrics["disagreements_total"] += 1
                    if obs.disagreement_category == DisagreementCategory.PRODUCTION_MALICIOUS_CASCADE_SAFE:
                        self._metrics["potential_fn_total"] += 1
            elif obs.shadow_status == ShadowStatus.TIMEOUT:
                self._metrics["timeouts_total"] += 1
            elif obs.shadow_status == ShadowStatus.DROPPED_CAPACITY:
                self._metrics["dropped_capacity_total"] += 1
            elif obs.shadow_status == ShadowStatus.ERROR:
                self._metrics["errors_total"] += 1

    async def execute_shadow_task(
        self,
        url: str,
        production_verdict: str,
        production_score: float,
    ) -> ShadowCascadeObservation:
        """
        Execute a single shadow cascade evaluation.

        Returns an observation record, even on timeout or error.
        """
        obs_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()
        url_hash = self._hash_str(url)
        host = URLNormalizer.extract_hostname(url)
        host_hash = self._hash_str(host)

        # Capacity check
        if self._semaphore.locked():
            obs = ShadowCascadeObservation(
                observation_id=obs_id,
                timestamp=ts,
                url_sha256=url_hash,
                hostname_sha256=host_hash,
                production_verdict=production_verdict,
                production_score=production_score,
                shadow_status=ShadowStatus.DROPPED_CAPACITY,
            )
            await self._record_observation(obs)
            return obs

        async with self._semaphore:
            try:
                timeout_sec = max(0.001, self.config.timeout_ms / 1000.0)
                cascade_res: CascadePredictionResult = await asyncio.wait_for(
                    self._cascade.predict_cascade(url),
                    timeout=timeout_sec,
                )

                disagreement = False
                disag_cat = DisagreementCategory.NONE
                norm_prod_v = production_verdict.upper()
                norm_casc_v = cascade_res.verdict.upper()
                if norm_prod_v != norm_casc_v:
                    disagreement = True
                    if norm_prod_v in ("MALICIOUS", "CRITICAL") and norm_casc_v == "SAFE":
                        disag_cat = DisagreementCategory.PRODUCTION_MALICIOUS_CASCADE_SAFE
                    elif norm_prod_v == "SAFE" and norm_casc_v in ("MALICIOUS", "CRITICAL"):
                        disag_cat = DisagreementCategory.PRODUCTION_SAFE_CASCADE_MALICIOUS
                    elif norm_prod_v == "SUSPICIOUS" and norm_casc_v == "SAFE":
                        disag_cat = DisagreementCategory.PRODUCTION_SUSPICIOUS_CASCADE_SAFE
                    elif norm_prod_v == "SAFE" and norm_casc_v == "SUSPICIOUS":
                        disag_cat = DisagreementCategory.PRODUCTION_SAFE_CASCADE_SUSPICIOUS
                    else:
                        disag_cat = DisagreementCategory.OTHER

                obs = ShadowCascadeObservation(
                    observation_id=obs_id,
                    timestamp=ts,
                    url_sha256=url_hash,
                    hostname_sha256=host_hash,
                    production_verdict=production_verdict,
                    cascade_verdict=cascade_res.verdict,
                    production_score=production_score,
                    cascade_score=cascade_res.final_score,
                    stage_reached=cascade_res.stage_reached.value,
                    heuristics_resolved=(cascade_res.stage_reached == CascadeStage.STAGE_HEURISTICS),
                    onnx_invoked=cascade_res.onnx_invoked,
                    urlbert_invoked=cascade_res.urlbert_invoked,
                    cascade_latency_ms=cascade_res.latency_ms,
                    shadow_status=ShadowStatus.SUCCESS,
                    disagreement=disagreement,
                    disagreement_category=disag_cat,
                    security_override_triggered=cascade_res.hard_override,
                )
                await self._record_observation(obs)
                return obs

            except asyncio.TimeoutError:
                obs = ShadowCascadeObservation(
                    observation_id=obs_id,
                    timestamp=ts,
                    url_sha256=url_hash,
                    hostname_sha256=host_hash,
                    production_verdict=production_verdict,
                    production_score=production_score,
                    shadow_status=ShadowStatus.TIMEOUT,
                    error="Shadow evaluation exceeded timeout limit",
                )
                await self._record_observation(obs)
                return obs

            except Exception as e:
                logger.warning("Shadow cascade execution error: %s", e)
                obs = ShadowCascadeObservation(
                    observation_id=obs_id,
                    timestamp=ts,
                    url_sha256=url_hash,
                    hostname_sha256=host_hash,
                    production_verdict=production_verdict,
                    production_score=production_score,
                    shadow_status=ShadowStatus.ERROR,
                    error=str(e),
                )
                await self._record_observation(obs)
                return obs

    async def observe_async(
        self,
        url: str,
        production_verdict: str,
        production_score: float,
    ) -> Optional[asyncio.Task]:
        """
        Schedule an observation if sampling conditions are met.

        Returns the asyncio Task, or None if skipped.
        """
        if not self.config.enabled:
            return None
        if self.config.sample_rate <= 0.0:
            return None
        if self.config.sample_rate < 1.0 and random.random() > self.config.sample_rate:
            return None
        return asyncio.create_task(
            self.execute_shadow_task(url, production_verdict, production_score)
        )

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Return a summary of metrics for this manager."""
        total = self._metrics["observations_total"]
        success = max(self._metrics["success_total"], 1)
        return {
            "enabled": self.config.enabled,
            "sample_rate": self.config.sample_rate,
            "timeout_ms": self.config.timeout_ms,
            "max_concurrency": self.config.max_concurrency,
            "observations_total": total,
            "success_total": self._metrics["success_total"],
            "timeouts_total": self._metrics["timeouts_total"],
            "dropped_capacity_total": self._metrics["dropped_capacity_total"],
            "errors_total": self._metrics["errors_total"],
            "disagreements_total": self._metrics["disagreements_total"],
            "potential_false_negatives_total": self._metrics["potential_fn_total"],
            "urlbert_invocation_rate_pct": round(
                (self._metrics["urlbert_invocations_total"] / success) * 100.0, 1
            ),
            "onnx_invocation_rate_pct": round(
                (self._metrics["onnx_invocations_total"] / success) * 100.0, 1
            ),
            "heuristics_resolution_rate_pct": round(
                (self._metrics["heuristics_resolved_total"] / success) * 100.0, 1
            ),
            "hard_rule_resolution_rate_pct": round(
                (self._metrics["hard_rules_resolved_total"] / success) * 100.0, 1
            ),
            "recent_observations_count": len(self._observations),
        }

    def get_latest_observations(self, count: int = 10) -> List[ShadowCascadeObservation]:
        """Return the most recent observations."""
        return list(self._observations)[-count:]