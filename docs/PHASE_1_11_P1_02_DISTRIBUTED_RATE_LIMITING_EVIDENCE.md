# ZeroPhish — Phase 1.11 / P1-02: Distributed Rate Limiting Implementation Evidence

## 1. Problem Statement
In multi-worker deployments (e.g. Uvicorn running with 4 or 8 workers behind a reverse proxy), the original rate limiter utilized process-local in-memory storage (`memory://`). Each gateway worker maintained its own rate-limit counters and sliding/fixed window states independently. Consequently, an adversary sending requests evenly distributed across $N$ workers could consume up to $N \times \text{Limit}$ requests per window. This violated rate limiting boundaries and exposed the underlying analysis tiers to denial-of-service and quota exhaustion.

P1-02 remedies this vulnerability by establishing Redis as the shared transient authority for rate-limit state across all gateway workers, enforcing atomic distributed counter increments and synchronized window expiry.

---

## 2. Distributed Architecture
ZeroPhish maintains a strict three-tier state architecture:
- **Shared-Durable:** PostgreSQL retains authoritative scan lifecycle records, user/auth details, incidents, and webhook configurations.
- **Shared-Transient:** Redis manages rate-limit window counters, atomic increment operations, and cross-worker SSE Pub/Sub message fanout.
- **Worker-Local Transient:** Process-local SSE subscriber queues and lightweight runtime metrics.

Gateway instances share the single authoritative Redis cluster specified via `REDIS_URL`. All route limits evaluated by SlowAPI coordinate directly against Redis key keyspaces (e.g. `LIMITER/<key>/<endpoint>/<window>`).

---

## 3. Storage Hierarchy & Production Contract
- **Production Mode (`ZEROPHISH_ENV=production`):**
  - Redis configuration (`REDIS_URL`) is mandatory.
  - Socket connect timeout is bounded to `3.0s` and socket read/write timeout to `5.0s`.
  - Missing or unreachable Redis at startup triggers a fatal `RuntimeError`, failing closed immediately.
  - Startup lifespan checks enforce the presence and validity of `REDIS_URL`.
- **Local Development / Test Fallback:**
  - When running in `development` or `test` without an active Redis daemon, `_create_gateway_limiter()` checks Redis connectivity via `storage.check()`.
  - If unreachable or omitted, it gracefully falls back to single-process in-memory storage (`memory://`), allowing unit tests and standalone developer workflows to run seamlessly.

---

## 4. Atomic Counter Semantics
SlowAPI utilizes Redis storage algorithms (via limits library) executing atomic `INCR` and `EXPIRE` commands (or Redis Lua scripts). Increments and window allocations are evaluated atomically inside the Redis engine. Concurrent requests across multiple workers or threads cannot read dirty un-incremented states or exceed configured thresholds.

---

## 5. Fail-Closed Behavior
When Redis experiences connection timeouts, network partitions, or storage errors at request time:
- The custom exception handler `rate_limit_redis_error_handler` catches `redis.exceptions.RedisError`.
- It immediately returns **HTTP 503 Service Unavailable** with JSON `{"error": "Service temporarily unavailable: rate limit storage error"}` and header `Retry-After: 5`.
- Requests are never allowed through unmetered in production when the limiter backend is down.
- Failures increment the `rate_limit_redis_errors_total` metric.

---

## 6. Monitored Endpoints & Coverage
The following public scan entry points and status endpoints are covered by the distributed rate limiter:
- `POST /gateway/scan` — Tier 1 & background analysis submission.
- `GET /gateway/status/{scan_id}` — Polling scan status.
- `GET /gateway/result/{scan_id}` — Polling full scan result.
- `POST /tier1/report` — Client reporting endpoint.

---

## 7. Metrics & Observability
Runtime rate limiting metrics are tracked and exposed:
- `rate_limit_rejected_total`: Total count of HTTP 429 rejections emitted by the gateway.
- `rate_limit_redis_errors_total`: Total count of Redis storage exceptions caught during rate limit evaluation.
- Exposed in `/gateway/health` under `"rate_limiting"`:
  ```json
  "rate_limiting": {
    "storage_backend": "redis",
    "rate_limit_redis_errors_total": 0,
    "rate_limit_rejected_total": 0
  }
  ```

---

## 8. Health & Readiness Probes
- `/gateway/health`: Emits gateway liveness along with current rate limit backend and metric counters.
- `/gateway/ready`: Actively probes Redis storage connectivity via `storage.check()`. In production, if the rate limiter storage probe fails, readiness transitions to `503 Service Unavailable` with `"rate_limiter": "unhealthy"`.

---

## 9. Security & Audit Logging
Whenever a request exceeds the configured threshold:
- `RateLimitExceeded` is captured by `rate_limit_handler`.
- Audit event is recorded via `security.audit_logger.log_rate_limited(client_ip, request.url.path)`.
- Client receives **HTTP 429 Too Many Requests** with informative JSON `{"error": "Rate limit exceeded: ..."}` and standard headers `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`.

---

## 10. Resource Safety & Graceful Shutdown
During FastAPI lifespan shutdown:
- Rate limiter storage connections (`_limiter.storage.storage`) are cleanly closed via `.close()`.
- Prevents connection leaks and orphaned sockets in worker pools.

---

## 11. Circular Import Elimination
`Backend/security/dependencies.py` was decoupled from `gateway.py` by implementing an independent `_get_security_limiter()` factory. This completely eliminates the previous circular import cycle (`gateway -> vision.router -> security.dependencies -> gateway`).

---

## 12. Verification & Test Suite
The dedicated test suite `Backend/tests/test_p1_02_distributed_rate_limiting.py` provides 100% deterministic coverage without external dependencies through `SharedFakeRedisStorage`:
1. `test_1_single_worker_baseline`: Standard single worker rate limiting.
2. `test_2_two_workers_shared_state`: Requests split between Worker A and Worker B respect the single global limit.
3. `test_3_multiple_workers_shared_state`: 4 workers sharing state accept exactly 5 requests and reject 7 requests out of 12.
4. `test_4_concurrent_requests_atomicity`: Multi-threaded burst requests across 20 threads adhere strictly to the atomic limit.
5. `test_5_window_expiration_resets_allowance`: Expired windows reset client allowance.
6. `test_6_independent_keys_isolation`: Different client IPs maintain independent allowances.
7. `test_7_redis_storage_failure_fails_closed`: Redis errors return 503 + Retry-After.
8. `test_8_missing_redis_url_production_contract`: Missing `REDIS_URL` in production fails closed at startup.
9. `test_9_local_development_fallback_semantics`: Non-production runs fall back gracefully to `memory://`.
10. `test_10_rate_limited_routes_coverage`: Verifies all critical scan and status routes are registered with rate limiting.
11. `test_11_cleanup_resource_safety_on_shutdown`: Storage connection `.close()` is called on app shutdown.
12. `test_12_existing_api_contract_response_format`: 429 response structure matches standard error contracts with `Retry-After`.

---

## 13. Regression Verification
The Phase 1.10 readiness regression test suite (`Backend/tests/test_phase1_10_readiness_regressions.py`) passed all 9 test cases cleanly:
- 21 total tests passed across `test_p1_02_distributed_rate_limiting.py` and `test_phase1_10_readiness_regressions.py`.
- No regressions observed in SSE subscriber cleanup, overflow tracking, or API key validation.

---

## 14. Summary of Changed Files
- `Backend/gateway.py`: Added distributed rate limiter factory `_create_gateway_limiter`, fail-closed error handler, Retry-After response handler, readiness/health probes, and graceful shutdown.
- `Backend/security/dependencies.py`: Resolved circular import by creating dedicated `_get_security_limiter`.
- `Backend/tests/test_p1_02_distributed_rate_limiting.py`: Full P1-02 test suite (12 tests).
- `docs/PHASE_1_11_P1_02_DISTRIBUTED_RATE_LIMITING_EVIDENCE.md`: Architecture and verification documentation.
