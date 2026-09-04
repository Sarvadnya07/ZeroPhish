"""
Regression and verification test suite for Clean-Code Refactoring Improvements.
Verifies:
1. Shadow cascade scheduling without TypeError in gateway scan flow.
2. CircuitBreaker HALF_OPEN concurrency isolation, single-flight probe, and fallback outside lock.
3. Repositories factory fail-closed behavior under ZEROPHISH_ENV=production.
4. Feed adapters truthful DEGRADED reporting on fixture fallback.
5. Deduplicated tier_2 benchmark alias module compatibility.
"""

import asyncio
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

from circuit_breaker import CircuitBreaker, CircuitBreakerOpenError, CircuitState
from repositories.factory import _check_production_persistence_requirement
from ml.data.schemas.v3 import FeedIngestionStatus, AdapterOperationalMode
from ml.data.adapters.feed_adapters import AdapterConfig, TrancoAdapter, OpenPhishAdapter, PhishTankAdapter
from ml.shadow.manager import ShadowCascadeManager


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_single_flight_and_probe_metric():
    """Verify that in HALF_OPEN state, only 1 probe is allowed in-flight."""
    cb = CircuitBreaker(failure_threshold=1, timeout=0.01, name="test_cb")

    # Trip to OPEN
    async def failing_func():
        raise RuntimeError("simulated upstream failure")

    with pytest.raises(RuntimeError):
        await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN

    # Wait for reset timeout to expire
    await asyncio.sleep(0.02)
    assert cb._should_attempt_reset() is True

    # Prepare a slow probe
    probe_started = asyncio.Event()
    probe_finish = asyncio.Event()

    async def slow_probe():
        probe_started.set()
        await probe_finish.wait()
        return "probe_success"

    async def concurrent_fallback():
        return "fallback_value"

    # Launch probe task
    probe_task = asyncio.create_task(cb.call(slow_probe))
    await probe_started.wait()

    assert cb.state == CircuitState.HALF_OPEN
    assert cb.metrics.half_open_probes == 1
    assert cb._half_open_probe_in_flight is True

    # Concurrent call while probe is in flight should be rejected (or use fallback)
    fallback_res = await cb.call(slow_probe, fallback=concurrent_fallback)
    assert fallback_res == "fallback_value"

    # Without fallback, should raise CircuitBreakerOpenError
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call(slow_probe)

    # Now let the probe finish
    probe_finish.set()
    probe_res = await probe_task
    assert probe_res == "probe_success"

    # Circuit should now be closed
    assert cb.state == CircuitState.CLOSED
    assert cb._half_open_probe_in_flight is False
    assert cb.metrics.half_open_successes == 1


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_probe_failure_reopens():
    """Verify that if the single probe fails in HALF_OPEN, it re-opens immediately."""
    cb = CircuitBreaker(failure_threshold=1, timeout=0.01, name="test_cb_fail")

    async def failing_func():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN
    await asyncio.sleep(0.02)

    with pytest.raises(RuntimeError):
        await cb.call(failing_func)

    assert cb.state == CircuitState.OPEN
    assert cb._half_open_probe_in_flight is False
    assert cb.metrics.half_open_failures == 1


def test_persistence_factory_zerophish_env_fail_closed():
    """Verify factory raises RuntimeError when ZEROPHISH_ENV=production without DATABASE_URL."""
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production"}, clear=False):
        if "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]
        if "ENV" in os.environ:
            del os.environ["ENV"]

        with pytest.raises(RuntimeError, match="DATABASE_URL must be configured in production environment"):
            _check_production_persistence_requirement()


def test_feed_adapter_truthful_degraded_status():
    """Verify feed adapter reports DEGRADED status when falling back to fixture."""
    adapter = TrancoAdapter()
    adapter.config = AdapterConfig(mode=AdapterOperationalMode.BULK_FILE, allow_fallback=True)
    assert adapter.get_feed_status() == FeedIngestionStatus.SUCCESS

    # Simulate network failure triggering fixture fallback
    with patch.object(adapter, "_safe_http_get", side_effect=OSError("Network unreachable")):
        records = adapter.fetch_records()
        assert len(records) > 0
        assert adapter.config.mode == AdapterOperationalMode.FIXTURE_FALLBACK
        assert adapter.get_feed_status() == FeedIngestionStatus.DEGRADED


def test_benchmark_alias_imports_successfully():
    """Verify tier_2.benchmark successfully forwards functions from benchmark_url_ml."""
    import tier_2.benchmark as bmark
    import tier_2.benchmark_url_ml as bmark_orig

    assert hasattr(bmark, "evaluate_predictions")
    assert hasattr(bmark, "main")
    assert bmark.evaluate_predictions is bmark_orig.evaluate_predictions


@pytest.mark.asyncio
async def test_shadow_cascade_direct_scheduling():
    """Verify observe_async returns Task or None and does not raise TypeError."""
    manager = ShadowCascadeManager.get_instance()
    # Ensure enabled with 100% sample rate for test
    manager.config.enabled = True
    manager.config.sample_rate = 1.0

    task = manager.observe_async(
        url="https://example-test-shadow.org/login",
        production_verdict="SAFE",
        production_score=0.1,
    )
    assert task is not None
    assert isinstance(task, asyncio.Task)
    obs = await task
    assert obs.production_verdict == "SAFE"
    assert obs.production_score == 0.1
    assert obs.observation_id is not None
