# ZeroPhish — Phase 1.11 / P1-02: Distributed Rate Limiting Implementation Evidence

## 1. Problem Statement & Root Cause Analysis

### 1.1 Root Causes
1. **Multi-Worker Rate Limiting Bypass:** The pre-P1-02 implementation relied on process-local in-memory state (`memory://`). Across $N$ gateway workers behind a load balancer, clients could consume up to $N \times \text{Limit}$ requests per window.
2. **Unsafe Production Fallback in Security Dependencies:** `Backend/security/dependencies.py` initialized a standalone Limiter used for routes like `/vision/analyze`. When `REDIS_URL` was absent or failed in development, it fell back to `memory://`, but its production contract lacked the strict enforcement applied to the gateway limiter, risking silent in-memory fallback in production.
3. **Lifespan Startup Connectivity Verification:** Startup previously validated only the syntactic existence of `REDIS_URL` in the environment, rather than performing an active reachability probe against the configured Redis cluster for all active limiters before serving requests.
4. **Lifecycle Resource Ownership & Teardown:** When closing limiter storage on shutdown, only the gateway limiter was inspected, and connection pools remained open unless explicitly disconnected.
5. **Exception Handling Hierarchy:** `slowapi` interacts with the underlying `limits` library, which can raise `limits.errors.StorageError` in addition to raw `redis.exceptions.RedisError`. Only `RedisError` was explicitly handled, creating a risk that wrapped storage errors might bubble up as generic 500s rather than 503 Service Unavailable with `Retry-After`.

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
| **Production (`ZEROPHISH_ENV=production`)** | **Mandatory.** Must provide valid `REDIS_URL`. | **Fails closed immediately:** Raises `RuntimeError` during factory init and lifespan probes for **both** limiters (`gateway.limiter` and `security.dependencies.limiter`). Application will not start or report ready. | **Fails closed:** Caught by `rate_limit_storage_error_handler`, returning **HTTP 503** + `Retry-After: 5`. Unmetered requests are never permitted. |
| **Development / Test** | Optional. Probes `REDIS_URL` if present. | Gracefully falls back to single-process in-memory backend (`memory://`) for both limiters. Logs clear warnings. | Caught by `rate_limit_storage_error_handler` if Redis is used; in-memory store operates locally. |

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
| `POST /vision/analyze` | `security.dependencies.limiter` | `RATE_LIMIT` (default `10/minute`) | `vision.router.analyze_screenshot` |

---

## 6. Test Suite & Verification Evidence

### 6.1 Unit Tests vs. Real-Redis Integration Tests
The test file `Backend/tests/test_p1_02_distributed_rate_limiting.py` contains:
- **Unit / Simulation Tests (12 tests):** Fast, deterministic tests executing against `SharedFakeRedisStorage` (simulating atomic Redis operations) and mock interfaces.
- **Real-Redis Integration Tests (2 tests):**
  1. `test_real_redis_cross_worker_rate_limiting_integration`: Verifies cross-worker coordination, shared state, and window TTL expiration against a live Redis daemon with unique isolated keyspaces (`TEST_RL_<uuid>`) and explicit key deletion cleanup.
  2. `test_real_redis_multiprocess_workers_cross_process_enforcement`: Spawns multiple real OS processes using `multiprocessing.Process` against a live Redis daemon to verify cross-process distributed enforcement across independent operating-system process memory boundaries.
  - Both integration tests are conditioned on `@pytest.mark.skipif(not _is_real_redis_available(), ...)` requiring `TEST_REAL_REDIS_URL`.

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
  - `test_8_missing_redis_url_production_contract`: **PASSED** (verifies missing `REDIS_URL` fails closed in gateway factory, security dependency factory, lifespan startup, unreachable gateway Redis startup probe, and unreachable security limiter startup probe)
  - `test_9_local_development_fallback_semantics`: **PASSED** (verifies gateway and security limiters cleanly fall back to `MemoryStorage` in development)
  - `test_10_rate_limited_routes_coverage`: **PASSED** (verifies policies across gateway and vision routes)
  - `test_11_cleanup_resource_safety_on_shutdown`: **PASSED** (verifies `.close()` and connection pool `.disconnect()` for **both** gateway and security limiter clients on app shutdown)
  - `test_12_existing_api_contract_response_format`: **PASSED** (verifies 429 status, JSON error, `Retry-After`, and `X-RateLimit-*` headers)
  - `test_real_redis_cross_worker_rate_limiting_integration`: **SKIPPED** (Reason: Live Redis instance not available on local workstation; set `TEST_REAL_REDIS_URL` in CI/staging)
  - `test_real_redis_multiprocess_workers_cross_process_enforcement`: **SKIPPED** (Reason: Live Redis instance not available on local workstation; set `TEST_REAL_REDIS_URL` in CI/staging)
- **Phase 1.10 Readiness Regression Suite:**
  - All 9 tests: **PASSED** (SSE lifecycle, subscriber cleanup, overflow management, API key auth)
- **Summary:** 21 passed, 2 skipped, 0 failed in 27.45s.

---

## 7. Lifecycle, Error Handling & Graceful Shutdown
- **Exception Handlers:**
  - Catches both `redis.exceptions.RedisError` and `limits.errors.StorageError`.
  - Translates storage failures to HTTP 503 with standard `Retry-After: 5` header and JSON error payload.
  - Rate limit rejections trigger `security.audit_logger.log_rate_limited`.
- **Resource Teardown:**
  - Fast lifespan shutdown inspects both `gateway.limiter` and `security.dependencies.limiter`, closing client handles via `.close()` and explicitly disconnecting underlying connection pools via `connection_pool.disconnect()`.

---

## 8. Files Changed & Git State
- **Branch:** `phase1.11/p1-02-distributed-rate-limiting`
- **Files Modified:**
  - `Backend/gateway.py`: Startup reachability probe for both gateway and security limiters in production lifespan, `StorageError` handling, resource teardown closing client and disconnecting pools for both limiters, robust storage scheme reporting in health/readiness, dynamic environment reporting.
  - `Backend/security/dependencies.py`: Unified `_resolve_limiter` enforcing fail-closed production contract with identical Redis timeouts, removing unsafe production fallback; added `close_security_limiter()` lifecycle cleanup.
  - `Backend/tests/test_p1_02_distributed_rate_limiting.py`: Extended tests for security dependency limiter, active startup failure on unreachable Redis for both limiters, storage client and pool disconnect teardown verification, route policies across routers, and live Redis integration test harness with unique keyspace isolation, key deletion cleanup, and true OS-multiprocess worker testing.
  - `docs/PHASE_1_11_P1_02_DISTRIBUTED_RATE_LIMITING_EVIDENCE.md`: Complete audit and evidence documentation.

---

## 9. Remaining Limitations & Explicitly Unproven Claims
1. **Live Network Redis Execution:** No live Redis daemon was active in this Windows local environment (`TEST_REAL_REDIS_URL` was unset). The test suite verified multi-worker concurrency and atomic increment semantics using the deterministic `SharedFakeRedisStorage`. Real TCP multi-process socket validation was explicitly marked **SKIPPED** and must run in a CI/staging environment with a provisioned Redis instance.
2. **Reverse Proxy IP Trust:** Rate limits use `request.client.host` via SlowAPI's `get_remote_address`. Behind load balancers (e.g., AWS ALB or Cloudflare), reverse proxies must be configured with trusted proxy headers so client IPs are not bundled into a single proxy IP.
