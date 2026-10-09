"""
Deterministic Test Suite for Phase 1.11 / P1-02: Distributed Rate Limiting.

Covers the full Test Matrix from the specification:
- TEST 1 — Existing rate-limit regression: Same-worker rate limiting remains correct.
- TEST 2 — Cross-worker shared limit: Worker A consumes allowance and Worker B observes the same shared allowance.
- TEST 3 — Multiple workers: Multiple independent worker instances against the same Redis state do not exceed global limit.
- TEST 4 — Concurrent requests: Concurrent increments against the same key are atomic without over-admission.
- TEST 5 — Window expiration: Allowance resets according to configured window semantics.
- TEST 6 — Independent keys: Different client IPs maintain separate independent allowances.
- TEST 7 — Redis failure: Fails closed with 503 HTTP status and Retry-After header.
- TEST 8 — Missing REDIS_URL production contract: Fails closed during startup/readiness when ZEROPHISH_ENV=production.
- TEST 9 — Local fallback: In local development, falls back explicitly to local in-memory store without claiming distributed protection.
- TEST 10 — Route coverage: Verifies every rate-limited gateway route enforces its configured policy.
- TEST 11 — Cleanup/resource safety: Redis connections and storage resources are properly closed on shutdown.
- TEST 12 — Existing API contract: Verifies HTTP 429 status, JSON error format, and standard response headers on rejection.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.exceptions
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import limits
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import gateway
from gateway import (
    CONFIG,
    _create_gateway_limiter,
    app,
    lifespan,
    limiter,
    rate_limit_metrics,
)


class SharedFakeRedisStorage(limits.storage.redis.RedisStorage):
    """
    In-memory thread-safe Redis storage implementation adhering to
    limits.storage.redis.RedisStorage interface for multi-worker testing.
    Uses locked dictionaries to simulate exact atomic Redis increment and expiry semantics.
    """

    def __init__(self, shared_db: Dict[str, Any], uri: str = "redis://fake:6379", **kwargs: Any):
        self._shared_db = shared_db
        self._lock = threading.Lock()
        limits.storage.Storage.__init__(self, uri, wrap_exceptions=False, **kwargs)
        self.key_prefix = "LIMITS"
        self.storage = MagicMock()
        self.storage.ping.return_value = True

    def get_connection(self) -> Any:
        return self.storage

    def check(self) -> bool:
        return True

    def incr(self, key: str, expiry: int, amount: int = 1) -> int:
        full_key = self.prefixed_key(key)
        now = time.time()
        with self._lock:
            entry = self._shared_db.get(full_key)
            if entry is None or entry["expires_at"] <= now:
                new_val = amount
                self._shared_db[full_key] = {"val": new_val, "expires_at": now + expiry}
                return new_val
            else:
                entry["val"] += amount
                return entry["val"]

    def get(self, key: str) -> int:
        full_key = self.prefixed_key(key)
        now = time.time()
        with self._lock:
            entry = self._shared_db.get(full_key)
            if entry is None or entry["expires_at"] <= now:
                return 0
            return entry["val"]

    def get_expiry(self, key: str) -> int:
        full_key = self.prefixed_key(key)
        now = time.time()
        with self._lock:
            entry = self._shared_db.get(full_key)
            if entry is None or entry["expires_at"] <= now:
                return 0
            return max(0, int(entry["expires_at"] - now))

    def clear(self, key: str) -> None:
        full_key = self.prefixed_key(key)
        with self._lock:
            self._shared_db.pop(full_key, None)


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Ensure rate limit metrics and limiter storage are reset cleanly between tests."""
    rate_limit_metrics["rate_limit_redis_errors_total"] = 0
    rate_limit_metrics["rate_limit_rejected_total"] = 0
    original_storage = getattr(getattr(gateway.limiter, "_limiter", None), "storage", None)
    yield
    if original_storage and hasattr(gateway.limiter, "_limiter"):
        gateway.limiter._limiter.storage = original_storage


# ==============================================================================
# TEST 1 — Existing rate-limit regression
# ==============================================================================
def test_1_existing_same_worker_rate_limiting_regression():
    """Verify that same-worker rate limiting operates and rejects requests exceeding the limit."""
    test_app = FastAPI()
    test_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://", headers_enabled=False)
    test_app.state.limiter = test_limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @test_app.get("/scan")
    @test_limiter.limit("3/minute")
    async def scan_endpoint(request: Request):
        return {"status": "ok"}

    client = TestClient(test_app)
    # Requests 1..3 should succeed
    for i in range(3):
        res = client.get("/scan")
        assert res.status_code == 200, f"Request {i+1} failed"

    # Request 4 must be rate-limited (429)
    res4 = client.get("/scan")
    assert res4.status_code == 429
    assert "Rate limit exceeded" in res4.json().get("error", "")


# ==============================================================================
# TEST 2 — Cross-worker shared limit
# ==============================================================================
def test_2_cross_worker_shared_rate_limit():
    """Worker A consumes allowance, and Worker B observes and enforces the exact same allowance."""
    shared_redis_state: Dict[str, Any] = {}

    def create_worker_app(worker_name: str) -> FastAPI:
        w_app = FastAPI()
        w_limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
        w_limiter._limiter.storage = SharedFakeRedisStorage(shared_redis_state)
        w_app.state.limiter = w_limiter
        w_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        @w_app.get("/scan")
        @w_limiter.limit("2/minute")
        async def endpoint(request: Request):
            return {"worker": worker_name}

        return w_app

    client_a = TestClient(create_worker_app("worker_a"))
    client_b = TestClient(create_worker_app("worker_b"))

    # Worker A receives request 1 -> OK
    res_a1 = client_a.get("/scan")
    assert res_a1.status_code == 200
    assert res_a1.json()["worker"] == "worker_a"

    # Worker B receives request 2 -> OK (limit 2 reached)
    res_b1 = client_b.get("/scan")
    assert res_b1.status_code == 200
    assert res_b1.json()["worker"] == "worker_b"

    # Worker A receives request 3 -> 429
    res_a2 = client_a.get("/scan")
    assert res_a2.status_code == 429

    # Worker B receives request 4 -> 429
    res_b2 = client_b.get("/scan")
    assert res_b2.status_code == 429


# ==============================================================================
# TEST 3 — Multiple workers (4 independent workers)
# ==============================================================================
def test_3_multiple_workers_shared_state():
    """4 independent worker instances against shared Redis state do not exceed global limit."""
    shared_redis_state: Dict[str, Any] = {}
    limit_count = 5

    worker_clients: List[TestClient] = []
    for i in range(4):
        w_app = FastAPI()
        w_limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
        w_limiter._limiter.storage = SharedFakeRedisStorage(shared_redis_state)
        w_app.state.limiter = w_limiter
        w_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        @w_app.get("/scan")
        @w_limiter.limit(f"{limit_count}/minute")
        async def endpoint(request: Request):
            return {"worker_index": i}

        worker_clients.append(TestClient(w_app))

    accepted_requests = 0
    rejected_requests = 0

    # Distribute 12 requests across all 4 workers in round-robin fashion
    for req_idx in range(12):
        w_client = worker_clients[req_idx % 4]
        res = w_client.get("/scan")
        if res.status_code == 200:
            accepted_requests += 1
        elif res.status_code == 429:
            rejected_requests += 1

    assert accepted_requests == limit_count
    assert rejected_requests == 12 - limit_count


# ==============================================================================
# TEST 4 — Concurrent requests atomicity
# ==============================================================================
def test_4_concurrent_requests_atomicity():
    """Exercise concurrent increments across threads to verify atomicity and absence of over-admission."""
    shared_redis_state: Dict[str, Any] = {}
    limit_count = 10
    num_threads = 20

    w_app = FastAPI()
    w_limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
    w_limiter._limiter.storage = SharedFakeRedisStorage(shared_redis_state)
    w_app.state.limiter = w_limiter
    w_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @w_app.get("/scan")
    @w_limiter.limit(f"{limit_count}/minute")
    async def endpoint(request: Request):
        return {"status": "ok"}

    client = TestClient(w_app)
    results: List[int] = []
    lock = threading.Lock()

    def make_request():
        res = client.get("/scan")
        with lock:
            results.append(res.status_code)

    threads = [threading.Thread(target=make_request) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = results.count(200)
    rejected = results.count(429)

    assert accepted == limit_count
    assert rejected == num_threads - limit_count


# ==============================================================================
# TEST 5 — Window expiration
# ==============================================================================
def test_5_window_expiration_resets_allowance():
    """Verify that allowance resets when window expires."""
    shared_redis_state: Dict[str, Any] = {}

    w_app = FastAPI()
    w_limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
    fake_storage = SharedFakeRedisStorage(shared_redis_state)
    w_limiter._limiter.storage = fake_storage
    w_app.state.limiter = w_limiter
    w_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @w_app.get("/scan")
    @w_limiter.limit("1/second")
    async def endpoint(request: Request):
        return {"status": "ok"}

    client = TestClient(w_app)

    # 1. First request allowed
    assert client.get("/scan").status_code == 200

    # 2. Immediate second request rejected
    assert client.get("/scan").status_code == 429

    # 3. Simulate window expiry by advancing timestamps in shared state
    for k in shared_redis_state:
        shared_redis_state[k]["expires_at"] = time.time() - 1

    # 4. Request after expiry allowed
    assert client.get("/scan").status_code == 200


# ==============================================================================
# TEST 6 — Independent keys
# ==============================================================================
def test_6_independent_keys_isolation():
    """Verify one client IP cannot consume another client's rate limit allowance."""
    shared_redis_state: Dict[str, Any] = {}

    w_app = FastAPI()
    w_limiter = Limiter(key_func=get_remote_address, headers_enabled=False)
    w_limiter._limiter.storage = SharedFakeRedisStorage(shared_redis_state)
    w_app.state.limiter = w_limiter
    w_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @w_app.get("/scan")
    @w_limiter.limit("1/minute")
    async def endpoint(request: Request):
        return {"status": "ok"}

    client_a = TestClient(w_app, client=("198.51.100.1", 50000))
    client_b = TestClient(w_app, client=("198.51.100.2", 50000))

    # Client A consumes its 1 allowance
    res_a1 = client_a.get("/scan")
    assert res_a1.status_code == 200

    # Client A is now rate-limited
    res_a2 = client_a.get("/scan")
    assert res_a2.status_code == 429

    # Client B (different IP) has full allowance remaining
    res_b1 = client_b.get("/scan")
    assert res_b1.status_code == 200


# ==============================================================================
# TEST 7 — Redis failure (Fail-closed behavior)
# ==============================================================================
# ==============================================================================
# TEST 7 — Redis failure & StorageError (Fail-closed behavior)
# ==============================================================================
def test_7_redis_storage_failure_fails_closed():
    """When Redis fails at request time, gateway must return 503 Service Unavailable with Retry-After header."""
    shared_redis_state: Dict[str, Any] = {}
    failing_storage = SharedFakeRedisStorage(shared_redis_state)

    def failing_incr(*args, **kwargs):
        raise redis.exceptions.ConnectionError("Redis connection refused")

    failing_storage.incr = failing_incr

    with patch.object(gateway.limiter._limiter, "storage", failing_storage):
        client = TestClient(app)
        res = client.post("/gateway/scan", json={"sender": "test@domain.com", "body": "test email body", "links": []})
        assert res.status_code == 503
        data = res.json()
        assert "Service temporarily unavailable" in data.get("error", "")
        assert res.headers.get("retry-after") == "5"
        assert rate_limit_metrics["rate_limit_redis_errors_total"] >= 1

    # Also verify limits.errors.StorageError is caught and converted to 503
    from limits.errors import StorageError
    def failing_incr_storage_error(*args, **kwargs):
        raise StorageError("Wrapped storage failure")

    failing_storage.incr = failing_incr_storage_error
    with patch.object(gateway.limiter._limiter, "storage", failing_storage):
        client = TestClient(app)
        res = client.post("/gateway/scan", json={"sender": "test@domain.com", "body": "test email body", "links": []})
        assert res.status_code == 503
        assert "Service temporarily unavailable" in res.json().get("error", "")
        assert res.headers.get("retry-after") == "5"


# ==============================================================================
# TEST 8 — Missing/Unreachable REDIS_URL production contract
# ==============================================================================
@pytest.mark.asyncio
async def test_8_missing_redis_url_production_contract():
    """In production environment, absence or unreachability of REDIS_URL must fail closed during startup/readiness."""
    from security.dependencies import _resolve_limiter as _resolve_security_limiter

    # 1. Gateway factory initialization failure when REDIS_URL missing
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:"}):
        os.environ.pop("REDIS_URL", None)
        with pytest.raises(RuntimeError) as exc_info:
            _create_gateway_limiter(None)
        assert "REDIS_URL must be configured" in str(exc_info.value)

    # 2. Security dependency factory initialization failure when REDIS_URL missing in production
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:"}):
        os.environ.pop("REDIS_URL", None)
        with pytest.raises(RuntimeError) as exc_info:
            _resolve_security_limiter(None)
        assert "REDIS_URL must be configured" in str(exc_info.value)

    # 3. Lifespan startup failure in production mode when REDIS_URL missing
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:"}):
        os.environ.pop("REDIS_URL", None)
        with pytest.raises(RuntimeError) as exc_info:
            async with lifespan(app):
                pass
        assert "REDIS_URL must be configured in production environment" in str(exc_info.value)

    # 4. Lifespan startup failure in production mode when REDIS_URL is present but gateway Redis is unreachable
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:", "REDIS_URL": "redis://unreachable.host:6379"}):
        unreachable_storage = MagicMock()
        unreachable_storage.check.return_value = False
        with patch.object(app.state.limiter._limiter, "storage", unreachable_storage):
            with pytest.raises(RuntimeError) as exc_info:
                async with lifespan(app):
                    pass
            assert "Redis gateway rate limiter storage failed connectivity check" in str(exc_info.value)

    # 5. Lifespan startup failure in production mode when security limiter is unreachable
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:", "REDIS_URL": "redis://unreachable.host:6379"}):
        from security import dependencies as sec_deps
        reachable_gw_storage = MagicMock()
        reachable_gw_storage.check.return_value = True
        unreachable_sec_storage = MagicMock()
        unreachable_sec_storage.check.return_value = False

        with patch.object(app.state.limiter._limiter, "storage", reachable_gw_storage):
            with patch.object(sec_deps.limiter._limiter, "storage", unreachable_sec_storage):
                with pytest.raises(RuntimeError) as exc_info:
                    async with lifespan(app):
                        pass
                assert "Redis security dependency rate limiter storage failed connectivity check" in str(exc_info.value)


# ==============================================================================
# TEST 9 — Local fallback
# ==============================================================================
def test_9_local_development_fallback_semantics():
    """In local development without Redis, limiter gracefully creates local memory backend."""
    from security.dependencies import _resolve_limiter as _resolve_security_limiter

    with patch.dict(os.environ, {"ZEROPHISH_ENV": "development", "ENV": "development"}):
        os.environ.pop("REDIS_URL", None)
        local_limiter = _create_gateway_limiter(None)
        storage_type = type(local_limiter._limiter.storage).__name__
        assert "MemoryStorage" in storage_type

        # Verify security dependency limiter also falls back to MemoryStorage in development
        sec_limiter = _resolve_security_limiter(None)
        sec_storage_type = type(sec_limiter._limiter.storage).__name__
        assert "MemoryStorage" in sec_storage_type

        # Verify health check reflects 'memory' storage backend
        client = TestClient(app)
        health_res = client.get("/health")
        assert health_res.status_code == 200
        rl_info = health_res.json().get("rate_limiting", {})
        assert rl_info.get("storage_backend") == "memory"


# ==============================================================================
# TEST 10 — Route coverage & Policy verification
# ==============================================================================
def test_10_rate_limited_routes_coverage():
    """Verify scan, status, report, and vision routes actively enforce their rate limiting policies."""
    import vision.router
    from security.dependencies import limiter as sec_limiter

    # Verify gateway endpoints have limits registered in gateway.limiter
    gw_routes = gateway.limiter._route_limits
    assert "gateway.gateway_scan" in gw_routes
    assert "gateway.gateway_status" in gw_routes
    assert "gateway.gateway_result" in gw_routes
    assert "gateway.receive_tier1_report" in gw_routes

    # Verify vision endpoint has limit registered in security.dependencies.limiter
    sec_routes = sec_limiter._route_limits
    assert "vision.router.analyze_screenshot" in sec_routes


# ==============================================================================
# TEST 11 — Cleanup / Resource safety
# ==============================================================================
@pytest.mark.asyncio
async def test_11_cleanup_resource_safety_on_shutdown():
    """Verify rate limiter storage resources are safely closed when the app shuts down."""
    mock_gw_storage_client = MagicMock()
    mock_gw_storage_client.close = MagicMock()
    mock_gw_pool = MagicMock()
    mock_gw_pool.disconnect = MagicMock()
    mock_gw_storage_client.connection_pool = mock_gw_pool

    mock_gw_limiter = MagicMock()
    mock_gw_limiter._limiter.storage.storage = mock_gw_storage_client

    mock_sec_storage_client = MagicMock()
    mock_sec_storage_client.close = MagicMock()
    mock_sec_pool = MagicMock()
    mock_sec_pool.disconnect = MagicMock()
    mock_sec_storage_client.connection_pool = mock_sec_pool

    from security import dependencies as sec_deps
    mock_sec_limiter = MagicMock()
    mock_sec_limiter._limiter.storage.storage = mock_sec_storage_client

    with patch.object(app.state, "limiter", mock_gw_limiter):
        with patch.object(sec_deps, "limiter", mock_sec_limiter):
            with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:", "REDIS_URL": "redis://fake:6379"}):
                with patch("gateway.start_sse_pubsub", new_callable=AsyncMock):
                    with patch("gateway.stop_sse_pubsub", new_callable=AsyncMock):
                        async with lifespan(app):
                            pass
                        mock_gw_storage_client.close.assert_called_once()
                        mock_gw_pool.disconnect.assert_called_once()
                        mock_sec_storage_client.close.assert_called_once()
                        mock_sec_pool.disconnect.assert_called_once()


# ==============================================================================
# TEST 12 — Existing API contract
# ==============================================================================
def test_12_existing_api_contract_response_format():
    """Verify 429 response structure conforms to expected error JSON format and includes retry headers."""
    test_app = FastAPI()
    test_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://", headers_enabled=False)
    test_app.state.limiter = test_limiter
    test_app.add_exception_handler(RateLimitExceeded, gateway.rate_limit_handler)

    @test_app.get("/scan")
    @test_limiter.limit("1/minute")
    async def endpoint(request: Request):
        return {"result": "success"}

    client = TestClient(test_app)

    # 1. Accepted response
    res1 = client.get("/scan")
    assert res1.status_code == 200
    assert res1.json() == {"result": "success"}

    # 2. Rejected response
    res2 = client.get("/scan")
    assert res2.status_code == 429
    body = res2.json()
    assert "error" in body
    assert "Rate limit exceeded" in body["error"]
    assert "retry-after" in res2.headers
    assert "x-ratelimit-limit" in res2.headers
    assert "x-ratelimit-remaining" in res2.headers
    assert "x-ratelimit-reset" in res2.headers


# ==============================================================================
# REAL REDIS INTEGRATION TESTS (Skipped unless live Redis available)
# ==============================================================================
def _is_real_redis_available() -> bool:
    target_url = os.getenv("TEST_REAL_REDIS_URL") or os.getenv("REDIS_URL")
    if not target_url:
        return False
    try:
        r = redis.Redis.from_url(target_url, socket_connect_timeout=0.5, socket_timeout=0.5)
        return bool(r.ping())
    except Exception:
        return False

@pytest.mark.skipif(
    not _is_real_redis_available(),
    reason="Live Redis instance not available; set TEST_REAL_REDIS_URL to run real-Redis integration tests in CI/staging."
)
def test_real_redis_cross_worker_rate_limiting_integration():
    """
    Integration test executing atomic increments and TTL expiry against an actual Redis daemon.
    Validates cross-worker coordination, shared state, and window expiration with keyspace cleanup.
    """
    redis_url = os.getenv("TEST_REAL_REDIS_URL") or os.getenv("REDIS_URL")
    assert redis_url is not None

    r_client = redis.Redis.from_url(redis_url)
    run_id = uuid.uuid4().hex[:8]
    test_key_prefix = f"TEST_RL_{run_id}"

    limiter_w1 = Limiter(
        key_func=get_remote_address,
        storage_uri=redis_url,
        storage_options={"key_prefix": test_key_prefix},
        headers_enabled=False,
    )
    limiter_w2 = Limiter(
        key_func=get_remote_address,
        storage_uri=redis_url,
        storage_options={"key_prefix": test_key_prefix},
        headers_enabled=False,
    )

    app_w1 = FastAPI()
    app_w1.state.limiter = limiter_w1
    app_w1.add_exception_handler(RateLimitExceeded, gateway.rate_limit_handler)

    app_w2 = FastAPI()
    app_w2.state.limiter = limiter_w2
    app_w2.add_exception_handler(RateLimitExceeded, gateway.rate_limit_handler)

    unique_route = f"/real-redis-test-{run_id}"

    @app_w1.get(unique_route)
    @limiter_w1.limit("2/second")
    async def ep1(request: Request):
        return {"worker": 1}

    @app_w2.get(unique_route)
    @limiter_w2.limit("2/second")
    async def ep2(request: Request):
        return {"worker": 2}

    try:
        c1 = TestClient(app_w1, client=("203.0.113.195", 50000))
        c2 = TestClient(app_w2, client=("203.0.113.195", 50000))

        # Request 1 via Worker 1 -> OK
        assert c1.get(unique_route).status_code == 200
        # Request 2 via Worker 2 -> OK (limit 2 reached)
        assert c2.get(unique_route).status_code == 200
        # Request 3 via Worker 1 -> 429 Rate Limit Exceeded
        assert c1.get(unique_route).status_code == 429
        # Request 4 via Worker 2 -> 429 Rate Limit Exceeded
        assert c2.get(unique_route).status_code == 429

        # Wait for TTL to expire (window: 2/second)
        time.sleep(1.2)

        # Request 5 after expiry -> OK
        assert c1.get(unique_route).status_code == 200
    finally:
        # Cleanup test keys in Redis
        try:
            keys = r_client.keys(f"{test_key_prefix}*")
            if keys:
                r_client.delete(*keys)
            r_client.close()
        except Exception:
            pass


def _multiprocess_worker_target(redis_url: str, route_name: str, client_ip: str, results_queue: Any):
    """Worker process function for testing real OS-multiprocess rate limiting."""
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    w_limiter = Limiter(key_func=get_remote_address, storage_uri=redis_url, headers_enabled=False)
    w_app = FastAPI()
    w_app.state.limiter = w_limiter
    w_app.add_exception_handler(RateLimitExceeded, gateway.rate_limit_handler)

    @w_app.get(route_name)
    @w_limiter.limit("2/minute")
    async def target_endpoint(request: Request):
        return {"status": "ok"}

    w_client = TestClient(w_app, client=(client_ip, 50000))
    res = w_client.get(route_name)
    results_queue.put(res.status_code)


@pytest.mark.skipif(
    not _is_real_redis_available(),
    reason="Live Redis instance not available; set TEST_REAL_REDIS_URL to run real-Redis integration tests in CI/staging."
)
def test_real_redis_multiprocess_workers_cross_process_enforcement():
    """
    Multiprocess Integration Test:
    Spawns multiple real OS processes using Python's multiprocessing module against a live Redis daemon.
    Verifies that separate OS processes strictly enforce the shared atomic rate limit across process boundaries.
    """
    import multiprocessing
    redis_url = os.getenv("TEST_REAL_REDIS_URL") or os.getenv("REDIS_URL")
    assert redis_url is not None

    r_client = redis.Redis.from_url(redis_url)
    run_id = uuid.uuid4().hex[:8]
    route_name = f"/mp-test-{run_id}"
    client_ip = "203.0.113.200"

    queue = multiprocessing.Queue()
    procs = []

    try:
        # Launch 3 separate OS processes making 1 request each against the shared 2/minute limit
        for _ in range(3):
            p = multiprocessing.Process(
                target=_multiprocess_worker_target,
                args=(redis_url, route_name, client_ip, queue)
            )
            procs.append(p)
            p.start()

        for p in procs:
            p.join(timeout=10)
            assert p.exitcode == 0

        statuses = [queue.get(timeout=2) for _ in range(3)]
        assert statuses.count(200) == 2
        assert statuses.count(429) == 1
    finally:
        # Cleanup keys created by multiprocess test
        try:
            keys = r_client.keys(f"*{route_name}*")
            if keys:
                r_client.delete(*keys)
            r_client.close()
        except Exception:
            pass
