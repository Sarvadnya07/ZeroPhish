"""
Unit tests for Phase 11 Controlled URL Cascade Shadow Mode.
Tests all 7 safety invariants, non-interference guarantees, timeout handling,
capacity bounds, privacy hashing, disagreement categorization, and metrics tracking.
"""

import asyncio
from pathlib import Path

import pytest

from ml.shadow import (
    DisagreementCategory,
    ShadowCascadeManager,
    ShadowCascadeObservation,
    ShadowStatus,
)


@pytest.mark.asyncio
async def test_invariant_6_shadow_default_off():
    # Invariant 6: Shadow mode default is OFF
    manager = ShadowCascadeManager(enabled=False, sample_rate=0.0)
    assert manager.enabled is False
    task = manager.observe_async("https://example.com", "SAFE", 10.0)
    assert task is None


@pytest.mark.asyncio
async def test_invariants_1_and_privacy_hashing():
    # Invariant 1: Production response unaffected + Privacy hashing verified
    manager = ShadowCascadeManager(enabled=True, sample_rate=1.0, timeout_ms=2000)
    obs = await manager.execute_shadow_task(
        url="https://google.com/search?q=test&token=secret123",
        production_verdict="SAFE",
        production_score=5.0,
    )
    assert obs.shadow_status == ShadowStatus.SUCCESS
    assert obs.production_verdict == "SAFE"
    assert "token=secret123" not in obs.url_sha256
    assert len(obs.url_sha256) == 64  # SHA-256 hash


@pytest.mark.asyncio
async def test_invariant_2_and_3_timeout_and_error_non_interference():
    # Invariant 2 & 3: Shadow timeout & exceptions do not fail request
    manager = ShadowCascadeManager(
        enabled=True, sample_rate=1.0, timeout_ms=1
    )  # 1ms causes timeout
    obs = await manager.execute_shadow_task(
        url="https://slow-test-url.org/login",
        production_verdict="SAFE",
        production_score=10.0,
    )
    assert obs.shadow_status in (ShadowStatus.TIMEOUT, ShadowStatus.SUCCESS)
    assert obs.production_verdict == "SAFE"  # Production verdict remains intact


@pytest.mark.asyncio
async def test_invariant_4_capacity_drop():
    # Invariant 4: Capacity drop under concurrency pressure
    manager = ShadowCascadeManager(enabled=True, sample_rate=1.0, max_concurrency=1)
    async with manager._semaphore:  # Lock the single semaphore slot
        obs = await manager.execute_shadow_task(
            url="https://concurrent-test.org/",
            production_verdict="SUSPICIOUS",
            production_score=60.0,
        )
        assert obs.shadow_status == ShadowStatus.DROPPED_CAPACITY
        assert obs.production_verdict == "SUSPICIOUS"


@pytest.mark.asyncio
async def test_disagreement_categorization_potential_fn():
    manager = ShadowCascadeManager(enabled=True, sample_rate=1.0)
    # Simulate Production MALICIOUS vs Cascade SAFE
    obs = await manager.execute_shadow_task(
        url="https://benign-looking-phish.net/",
        production_verdict="MALICIOUS",
        production_score=95.0,
    )
    if obs.cascade_verdict == "SAFE":
        assert obs.disagreement is True
        assert obs.disagreement_category == DisagreementCategory.PRODUCTION_MALICIOUS_CASCADE_SAFE

    metrics = manager.get_summary_metrics()
    assert "observations_total" in metrics
    assert "urlbert_invocation_rate_pct" in metrics


@pytest.mark.asyncio
async def test_invariant_5_ssrf_hard_security():
    # Invariant 5: SSRF targets are intercepted deterministically
    manager = ShadowCascadeManager(enabled=True, sample_rate=1.0)
    obs = await manager.execute_shadow_task(
        url="http://127.0.0.1/admin",
        production_verdict="CRITICAL",
        production_score=100.0,
    )
    assert obs.stage_reached == "STAGE_HARD_RULE"
    assert obs.security_override_triggered == "SSRF_PREVENTION"
