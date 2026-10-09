# ZeroPhish — Phase 1.11 / P1-02: Distributed Rate Limiting Implementation Evidence

## 1. Problem Statement & Root Cause Analysis

### 1.1 Root Causes
1. **Multi-Worker Rate Limiting Bypass:** The pre-P1-02 implementation relied on process-local in-memory state (`memory://`). Across $N$ gateway workers behind a load balancer, clients could consume up to $N \times \text{Limit}$ requests per window.
2. **Unsafe Production Fallback in Security Dependencies:** `Backend/security/dependencies.py` initialized a standalone Limiter used for routes like `/vision/analyze`. When `REDIS_URL` was absent or failed in development, it fell back to `memory://`, but its production contract lacked the strict enforcement applied to the gateway limiter, risking silent fallback in production.
3. **Lifespan Startup Connectivity Verification:** Startup previously validated only the syntactic existence of `REDIS_URL` in the environment, rather than performing an active reachability probe against the configured Redis cluster before serving requests.
4. **Exception Handling Hierarchy:** `slowapi` interacts with the underlying `limits` library, which can raise `limits.errors.StorageError` in addition to raw `redis.exceptions.RedisError`. Only `RedisError` was explicitly handled, creating a risk that wrapped storage errors might bubble up as generic 500s rather than 503 Service Unavailable with `Retry-After`.

---

## 2. Distributed Architecture & State Separation

ZeroPhish strictly enforces state segregation across tiers:
- **Shared-Durable (PostgreSQL):** Authoritative scan records, durable incidents, user models, webhook subscriptions.
- **Shared-Transient (Redis):** Distributed rate-limiting counters/windows and cross-worker SSE Pub/Sub fanout.
- **Worker-Local Transient:** Memory-resident subscriber queues and ephemeral runtime telemetry.

Redis is the sole transient authority for rate limits across all gateway workers. Both the primary gateway limiter (`gateway.limiter`) and the security dependency limiter (`security.dependencies.limiter`) enforce identical Redis configuration standards and timeouts (`3.0s` connect, `5.0s` read).

---

## 3. Production vs. Development Runtime Behavior

| Environment | Redis Configuration | Connectivity Failure at Startup | Request-Time Storage Failure |
| :--- | :--- | :--- | :--- |
| **Production (`ZEROPHISH_ENV=production`)** | **Mandatory.** Must provide valid `REDIS_URL`. | **Fails closed immediately:** Raises `RuntimeError` during factory init and lifespan probe. Application will not start or report ready. | **Fails closed:** Caught by `rate_limit_storage_error_handler`, returning **HTTP 503** + `Retry-After: 5`. Unmetered requests are never permitted. |
| **Development / Test** | Optional. Probes `REDIS_URL` if present. | Gracefully falls back to single-process in-memory backend (`memory://`). Logs clear warning. | Caught by `rate_limit_storage_error_handler` if Redis is used; in-memory store operates locally. |

---

## 4. Health, Readiness & Observability Contracts

### 4.1 `/gateway/health`
Exposes the effective environment, current storage scheme, and rate-limiting metrics:
```json
{
  "status": "healthy",
  "service": "ZeroPhish API Gateway",
  "environment": "production",
  "rate_limiting": {
    "storage_backend": "redis",
    "rate_limit_redis_errors_total": 0,
    "rate_limit_rejected_total": 0
  }
}
```

### 4.2 `/gateway/ready`
Performs active ping probes against:
- Database (`SELECT 1`)
- Redis Pub/Sub (`ping()`)
- Rate Limiter storage (`storage.check()`)

If `storage.check()` fails in production, `/gateway/ready` returns **HTTP 503 Service Unavailable** with `"dependencies": {"rate_limiter": "unhealthy"}`.

---

## 5. Route Policies & Verified Endpoints

The rate limiting policies are registered on the authoritative limiters:

| Endpoint | Limiter Instance | Configured Policy / Variable | Verified Key / Function |
| :--- | :--- | :--- | :--- |
| `POST /gateway/scan` | `gateway.limiter` | `CONFIG.scan_rate_limit` (`20/minute` prod, `1200/minute` dev) | `gateway.gateway_scan` |
| `GET /gateway/status/{scan_id}` | `gateway.limiter` | `CONFIG.status_rate_limit` (`120/minute`) | `gateway.gateway_status` |
| `GET /gateway/result/{scan_id}` | `gateway.limiter` | `CONFIG.status_rate_limit` (`120/minute`) | `gateway.gateway_result` |
| `POST /tier1/report` | `gateway.limiter` | `CONFIG.status_rate_limit` (`120/minute`) | `gateway.receive_tier1_report` |
| `POST /vision/analyze` | `security.dependencies.limiter` | `VISION_RATE_LIMIT` (default `10/minute`) | `vision.router.analyze_screenshot` |

---

## 6. Test Suite & Verification Evidence

### 6.1 Unit Tests vs. Real-Redis Integration Tests
The test file `Backend/tests/test_p1_02_distributed_rate_limiting.py` contains:
- **Unit / Simulation Tests (12 tests):** Fast, deterministic tests executing against `SharedFakeRedisStorage` (simulating atomic Redis operations) and mock interfaces.
- **Real-Redis Integration Test (1 test):** `test_real_redis_cross_worker_rate_limiting_integration` exercises two independent gateway applications backed by a real Redis instance over network sockets. It is conditionally executed via `@pytest.mark.skipif(not _is_real_redis_available(), ...)` when `TEST_REAL_REDIS_URL` is set.

### 6.2 Test Execution Results
Executed test run:
```bash
python -m pytest Backend/tests/test_p1_02_distributed_rate_limiting.py Backend/tests/test_phase1_10_readiness_regressions.py -v --no-cov
```

**Results:**
- **P1-02 Distributed Rate Limiting Suite:**
  - `test_1_single_worker_baseline`: **PASSED**
  - `test_2_two_workers_shared_state`: **PASSED**
  - `test_3_multiple_workers_shared_state`: **PASSED**
  - `test_4_concurrent_requests_atomicity`: **PASSED**
  - `test_5_window_expiration_resets_allowance`: **PASSED**
  - `test_6_independent_keys_isolation`: **PASSED**
  - `test_7_redis_storage_failure_fails_closed`: **PASSED** (verifies both `redis.exceptions.ConnectionError` and `limits.errors.StorageError` return 503 + Retry-After)
  - `test_8_missing_redis_url_production_contract`: **PASSED** (verifies missing `REDIS_URL` fails closed in gateway factory, security dependency factory, lifespan startup, and unreachable Redis startup probe)
  - `test_9_local_development_fallback_semantics`: **PASSED** (verifies gateway and security limiters cleanly fall back to `MemoryStorage` in development)
  - `test_10_rate_limited_routes_coverage`: **PASSED** (verifies policies across gateway and vision routes)
  - `test_11_cleanup_resource_safety_on_shutdown`: **PASSED** (verifies `.close()` lifecycle on app shutdown)
  - `test_12_existing_api_contract_response_format`: **PASSED** (verifies 429 status, JSON error, `Retry-After`, and `X-RateLimit-*` headers)
  - `test_real_redis_cross_worker_rate_limiting_integration`: **SKIPPED** (Reason: Live Redis instance not available on local Windows dev workstation without `TEST_REAL_REDIS_URL`)
- **Phase 1.10 Readiness Regression Suite:**
  - All 9 tests: **PASSED** (SSE lifecycle, subscriber cleanup, overflow management, API key auth)
- **Summary:** 21 passed, 1 skipped, 0 failed in 35.39s.

---

## 7. Lifecycle, Error Handling & Graceful Shutdown
- **Exception Handlers:**
  - Catches both `redis.exceptions.RedisError` and `limits.errors.StorageError`.
  - Translates storage failures to HTTP 503 with standard `Retry-After: 5` header and JSON error payload.
  - Rate limit rejections trigger `security.audit_logger.log_rate_limited`.
- **Resource Teardown:**
  - Fast lifespan shutdown inspects `app.state.limiter` and terminates underlying Redis client connections via `storage.close()` if available.

---

## 8. Files Changed & Git State
- **Branch:** `phase1.11/p1-02-distributed-rate-limiting`
- **Files Modified:**
  - `Backend/gateway.py`: Production active Redis connectivity probe in lifespan, `StorageError` handling, robust storage scheme reporting in health/readiness, dynamic environment reporting.
  - `Backend/security/dependencies.py`: Unified `_resolve_limiter` enforcing fail-closed production contract with identical Redis timeouts, removing unsafe production fallback.
  - `Backend/tests/test_p1_02_distributed_rate_limiting.py`: Extended tests for security dependency limiter, active startup failure on unreachable Redis, `StorageError` 503 handling, route policies across routers, and live Redis integration test harness.
  - `docs/PHASE_1_11_P1_02_DISTRIBUTED_RATE_LIMITING_EVIDENCE.md`: Complete audit and evidence documentation.

---

## 9. Remaining Limitations & Explicitly Unproven Claims
1. **Live Multi-Node Redis Cluster Testing:** The real-Redis integration test was skipped in this local Windows development environment because no local Redis server was running (`TEST_REAL_REDIS_URL` not set). Simulated multi-worker and concurrent atomicity tests passed 100%, but live-network Redis testing must run in CI/staging where Redis is provisioned.
2. **Reverse Proxy Header Trust:** `key_func=get_remote_address` uses `request.client.host`. In environments behind reverse proxies (e.g. AWS ALB, Cloudflare), trusted proxy middleware must populate client host from `X-Forwarded-For` to prevent shared client IP pooling across external users.
