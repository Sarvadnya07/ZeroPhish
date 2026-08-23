"""
Configuration for Extended URL Cascade Shadow Mode.
Defines rollout modes, staged sample rates (10%, 25%, 50%, 100%),
timeouts, concurrency caps, and privacy/retention policies.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ShadowMode(str, Enum):
    OFF = "OFF"
    STAGING = "STAGING"
    PRODUCTION_SHADOW = "PRODUCTION_SHADOW"


class RolloutStage(str, Enum):
    STAGE_10 = "10%"
    STAGE_25 = "25%"
    STAGE_50 = "50%"
    STAGE_100 = "100%"


class ShadowConfig(BaseModel):
    mode: ShadowMode = Field(default=ShadowMode.OFF)
    sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    timeout_ms: int = Field(default=2000, ge=10)
    max_concurrency: int = Field(default=10, ge=1)
    retention_days: int = Field(default=14, ge=1)
    max_memory_observations: int = Field(default=5000, ge=100)
    strict_privacy_hashing: bool = True
    alert_on_potential_fn: bool = True

    @classmethod
    def from_env(cls) -> ShadowConfig:
        mode_str = os.getenv("ZEROPHISH_CASCADE_SHADOW_MODE", "OFF").upper()
        mode = ShadowMode.OFF
        if mode_str in ("STAGING", "PRODUCTION_SHADOW", "TRUE", "1", "ON"):
            mode = (
                ShadowMode.STAGING
                if mode_str == "STAGING"
                else (
                    ShadowMode.PRODUCTION_SHADOW
                    if mode_str == "PRODUCTION_SHADOW"
                    else ShadowMode.STAGING
                )
            )

        sample_rate = float(os.getenv("ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE", "0.0"))
        timeout_ms = int(os.getenv("CASCADE_SHADOW_TIMEOUT_MS", "2000"))
        max_concurrency = int(os.getenv("MAX_SHADOW_CASCADE_CONCURRENCY", "10"))

        return cls(
            mode=mode,
            sample_rate=sample_rate,
            timeout_ms=timeout_ms,
            max_concurrency=max_concurrency,
        )
