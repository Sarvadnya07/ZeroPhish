"""
Configuration for Extended URL Cascade Shadow Mode.

Defines rollout modes, staged sample rates (10%, 25%, 50%, 100%),
timeouts, concurrency caps, and privacy/retention policies.

All configuration is environment‑driven with sensible defaults.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ShadowMode(str, Enum):
    """Shadow mode enumeration."""
    OFF = "OFF"
    STAGING = "STAGING"
    PRODUCTION_SHADOW = "PRODUCTION_SHADOW"


class RolloutStage(str, Enum):
    """Rollout stage with corresponding sample rate."""
    STAGE_10 = "10%"
    STAGE_25 = "25%"
    STAGE_50 = "50%"
    STAGE_100 = "100%"

    @property
    def sample_rate(self) -> float:
        """Convert stage to sample rate."""
        rates = {
            "10%": 0.10,
            "25%": 0.25,
            "50%": 0.50,
            "100%": 1.00,
        }
        return rates.get(self.value, 0.0)


class ShadowConfig(BaseModel):
    """
    Shadow configuration with validation and environment loading.

    Attributes:
        mode: Shadow mode (OFF, STAGING, PRODUCTION_SHADOW).
        sample_rate: Fraction of requests to shadow (0.0 - 1.0).
        timeout_ms: Maximum time per shadow observation (ms).
        max_concurrency: Maximum concurrent shadow observations.
        retention_days: Days to retain shadow data.
        max_memory_observations: Max observations held in memory.
        strict_privacy_hashing: Whether to hash PII before storage.
        alert_on_potential_fn: Whether to alert on potential false negatives.
    """

    mode: ShadowMode = Field(default=ShadowMode.OFF)
    sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    timeout_ms: int = Field(default=2000, ge=10, le=30000)
    max_concurrency: int = Field(default=10, ge=1, le=100)
    retention_days: int = Field(default=14, ge=1, le=365)
    max_memory_observations: int = Field(default=5000, ge=100, le=100000)
    strict_privacy_hashing: bool = True
    alert_on_potential_fn: bool = True

    @field_validator("sample_rate")
    @classmethod
    def validate_sample_rate(cls, v: float) -> float:
        """Ensure sample_rate is consistent with mode."""
        return min(max(v, 0.0), 1.0)

    @classmethod
    def from_env(cls, mode_override: Optional[ShadowMode] = None) -> ShadowConfig:
        """
        Load configuration from environment variables.

        Environment variables:
            ZEROPHISH_CASCADE_SHADOW_MODE: OFF | STAGING | PRODUCTION_SHADOW
            ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE: float (0.0 - 1.0)
            CASCADE_SHADOW_TIMEOUT_MS: int
            MAX_SHADOW_CASCADE_CONCURRENCY: int
            SHADOW_RETENTION_DAYS: int
            SHADOW_MAX_MEMORY_OBSERVATIONS: int
            SHADOW_STRICT_PRIVACY: true | false
            SHADOW_ALERT_ON_FN: true | false
        """
        mode_str = os.getenv("ZEROPHISH_CASCADE_SHADOW_MODE", "OFF").upper()
        if mode_override is not None:
            mode = mode_override
        elif mode_str in ("STAGING", "PRODUCTION_SHADOW", "TRUE", "1", "ON"):
            mode = ShadowMode.STAGING if mode_str == "STAGING" else ShadowMode.PRODUCTION_SHADOW
        else:
            mode = ShadowMode.OFF

        # Sample rate
        sample_rate = float(os.getenv("ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE", "0.0"))
        if mode == ShadowMode.OFF:
            sample_rate = 0.0
        elif mode == ShadowMode.STAGING and sample_rate == 0.0:
            sample_rate = 0.10  # Default staging sample rate

        # Timeout
        timeout_ms = int(os.getenv("CASCADE_SHADOW_TIMEOUT_MS", "2000"))
        if timeout_ms < 10:
            timeout_ms = 2000

        # Concurrency
        max_concurrency = int(os.getenv("MAX_SHADOW_CASCADE_CONCURRENCY", "10"))
        if max_concurrency < 1:
            max_concurrency = 10

        # Retention
        retention_days = int(os.getenv("SHADOW_RETENTION_DAYS", "14"))
        if retention_days < 1:
            retention_days = 14

        # Memory limit
        max_memory = int(os.getenv("SHADOW_MAX_MEMORY_OBSERVATIONS", "5000"))
        if max_memory < 100:
            max_memory = 5000

        # Privacy hashing
        strict_privacy = os.getenv("SHADOW_STRICT_PRIVACY", "true").lower() in ("true", "1", "yes")

        # Alert on false negatives
        alert_on_fn = os.getenv("SHADOW_ALERT_ON_FN", "true").lower() in ("true", "1", "yes")

        return cls(
            mode=mode,
            sample_rate=sample_rate,
            timeout_ms=timeout_ms,
            max_concurrency=max_concurrency,
            retention_days=retention_days,
            max_memory_observations=max_memory,
            strict_privacy_hashing=strict_privacy,
            alert_on_potential_fn=alert_on_fn,
        )

    @classmethod
    def for_stage(cls, stage: RolloutStage) -> ShadowConfig:
        """Create a config for a specific rollout stage."""
        return cls(
            mode=ShadowMode.PRODUCTION_SHADOW,
            sample_rate=stage.sample_rate,
            timeout_ms=2000,
            max_concurrency=10,
            retention_days=14,
            max_memory_observations=5000,
            strict_privacy_hashing=True,
            alert_on_potential_fn=True,
        )

    def to_dict(self) -> dict:
        """Convert config to a dictionary for logging."""
        return {
            "mode": self.mode.value,
            "sample_rate": self.sample_rate,
            "timeout_ms": self.timeout_ms,
            "max_concurrency": self.max_concurrency,
            "retention_days": self.retention_days,
            "max_memory_observations": self.max_memory_observations,
            "strict_privacy_hashing": self.strict_privacy_hashing,
            "alert_on_potential_fn": self.alert_on_potential_fn,
        }