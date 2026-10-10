# Phase 1.11 / P1-03 — Gateway Scan Audit Trail Evidence

## 1. Overview & Objective

P1-03 establishes a durable, tamper-evident, security-conscious audit trail for gateway scan lifecycle events that survives process restarts and cross-worker execution without relying solely on process-local memory or ephemeral Redis pub/sub.

Branch: `phase1.11/p1-03-gateway-scan-audit-trail`  
Base Baseline: `0b75d16753423f9e95396ccc65ba496214feb38d` (origin/main)

---

## 2. Architecture & Design Principles

### 2.1 State Authority & Seams
- **Authoritative Durable Store**: Relational database table `scan_audit_events` managed by SQLAlchemy ORM and Alembic migration `0002_scan_audit_trail`.
- **Repository Abstraction**: `ScanAuditRepository` protocol in `Backend/repositories/base.py`, implemented by `SQLScanAuditRepository` in `Backend/repositories/sql_repositories.py` and `InMemoryScanAuditRepository` in `Backend/repositories/in_memory.py`.
- **Factory Wiring**: `get_scan_audit_repository()`, `set_scan_audit_repository()`, and `reset_repositories()` in `Backend/repositories/factory.py`, maintaining strict fail-closed enforcement in production if `DATABASE_URL` is omitted.
- **Dual-Emission Logging**: Every lifecycle audit event is recorded both into the durable repository and emitted to the structured `security.scan` logger namespace via `log_scan_audit`.

### 2.2 Event Contract
The event contract is modeled via `ScanAuditEvent` (`Backend/models/gateway_models.py`):
- `event_id`: Unique UUIDv4 string per audit record.
- `scan_id`: Associated scan identifier (or `"invalid"` / `"unauthorized"` for pre-creation failures).
- `event_type`: Categorized event types:
  - `SCAN_ACCEPTED`: Scan submitted and passed initial heuristic/Tier 2 validation.
  - `SCAN_CACHE_HIT`: Scan matched precomputed result in cache.
  - `SCAN_STAGE_TRANSITION`: State transitions across tiers.
  - `SCAN_COMPLETED`: Scan successfully finalized with fused score and verdict.
  - `SCAN_FAILED`: Background AI provider exception or fatal runtime error during finalization.
  - `SCAN_TIMEOUT`: Tier 3 AI analysis or downstream pipeline timed out.
  - `SCAN_VALIDATION_FAILED`: Schema or input validator rejected the payload.
  - `AUTHZ_DENIED`: Invalid or missing API key on scan endpoints.
- `correlation_id`: Propagated from `X-Correlation-ID` or `X-Request-ID` HTTP headers, or generated.
- `actor_id`: Hashed API key (e.g. `apikey:sha256(...)[:16]`) or authenticated `user_id`. Raw secrets and keys are never stored.
- `tenant_id`: Bound only from authenticated `request.state.tenant_id`. Unauthenticated client headers like `X-Tenant-ID` are explicitly discarded as untrusted client claims; in default single-tenant deployment `tenant_id` is `None`.
- `previous_state` & `new_state`: Explicit lifecycle state machine tracking (`SUBMITTED`, `PROCESSING`, `COMPLETED`, `FAILED`, `TIMEOUT`, `VALIDATION_FAILED`, `AUTHZ_DENIED`, `CACHE_HIT`).
- `verdict` & `score`: Verdict and numeric score at this lifecycle stage.
- `duration_ms`: Duration of execution stage in milliseconds.
- `error_category`: Standardized taxonomy (`INPUT_VALIDATION_ERROR`, `REQUEST_VALIDATION_ERROR`, `UNAUTHORIZED_API_KEY`, `AI_TIMEOUT`, `AI_PROVIDER_ERROR`, `UNEXPECTED_FINALIZER_EXCEPTION`).
- `provenance`: Gateway worker ID (`WORKER_ID`).
- `details`: Structured sanitized metadata dictionary.

### 2.3 Sanitization, Privacy Boundaries, and Failure Policy
- **Zero Raw Secret Storage**: Raw API keys, tokens, and authorization headers are never logged or stored; only hashed digests (`apikey:<16 hex>`) are persisted.
- **Zero Payload Leaks**: Full email bodies, recipient lists, and passwords are excluded from audit records.
- **Safe Serialization**: Structured error taxonomies and exception types are recorded rather than unvalidated exception dumps.
- **Durable Persistence Failure Policy**:
  - In production (`ZEROPHISH_ENV=production`), synchronous scan lifecycle events (`SCAN_ACCEPTED`, `SCAN_CACHE_HIT`) fail closed (`HTTP 500: Security audit logging failure: cannot persist required scan audit trail`) if the durable store write fails.
  - Background finalizer lifecycle logging records errors observably with `persistence_status="failed"` without crashing response delivery.
  - In production, unconfigured `API_KEY` fails closed (`HTTP 500: Server security misconfiguration: API key authentication must be configured in production`).
- **Resource Bounding & Access Control**:
  - Audit query endpoints enforce `limit: int = Query(default=50, ge=1, le=100)`, returning HTTP 422 for non-positive or excessive limits.
  - Audit queries verify existence of the requested `scan_id` via the scan repository, returning HTTP 404 for unknown or unauthorized identifiers.

---

## 3. Database Migration & Alembic Check

- Migration: `Backend/migrations/versions/0002_scan_audit_trail.py`
- Down Revision: `0001_initial_schema`
- Verified bidirectional schema compatibility:
  - `alembic upgrade head`: successfully creates `scan_audit_events` and associated indexes.
  - `alembic check`: clean ("No new upgrade operations detected").
  - `alembic downgrade -1`: successfully drops indexes and table.
  - `alembic upgrade head`: re-applies cleanly.

---

## 4. Verification & Test Evidence

Test execution was performed using the active Python 3.13 environment:

```text
C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe -m pytest \
    Backend/tests/test_p1_01a_lifecycle.py \
    Backend/tests/test_p1_01b_sse_cross_worker.py \
    Backend/tests/test_p1_02_distributed_rate_limiting.py \
    Backend/tests/test_audit_logger.py \
    Backend/tests/test_p1_03_gateway_scan_audit_trail.py \
    -o addopts=""
```

### 4.1 Test Results Summary

| Test Module | Tests Run | Result | Notes |
|---|---|---|---|
| `test_p1_01a_lifecycle.py` | 11 | Passed | Shared lifecycle, estimation, durability |
| `test_p1_01b_sse_cross_worker.py` | 11 | Passed | SSE cross-worker propagation and backpressure |
| `test_p1_02_distributed_rate_limiting.py` | 13 | Passed (2 skipped) | Rate limiting (skipped: external live Redis tests) |
| `test_audit_logger.py` | 1 | Passed | Security audit logger baseline |
| `test_p1_03_gateway_scan_audit_trail.py` | 13 | Passed | End-to-end audit lifecycle verification & review hardening |
| **Total** | **49 Passed, 2 Skipped** | **ALL GREEN** | |

### 4.2 Specific P1-03 Coverage Highlights
- `test_audit_logger_scan_events_structured_logging`: Validates structured logging across all scan lifecycle security events.
- `test_in_memory_scan_audit_repository_crud_and_deduplication`: Verifies deduplication by `event_id`, bounded memory storage, and list filtering.
- `test_sql_scan_audit_repository_durability_and_restart`: Verifies persistent storage across session factories and process reload simulations.
- `test_gateway_scan_lifecycle_auditing_end_to_end`: Tests HTTP scan submission resulting in durable `SCAN_ACCEPTED` record and retrieval via `/api/v1/scan/{scan_id}/audit`, verifying spoofed client headers are ignored (`tenant_id is None`).
- `test_gateway_scan_validation_failure_audit`: Tests malformed payloads producing `SCAN_VALIDATION_FAILED` audit records.
- `test_gateway_scan_authz_denied_audit`: Tests rejected API keys generating `AUTHZ_DENIED` with hashed key representation.
- `test_gateway_scan_cache_hit_audit`: Tests cache fast path generating `SCAN_CACHE_HIT` records.
- `test_audit_event_finalization_failure_and_timeout_classification`: Tests `SCAN_TIMEOUT` and `SCAN_FAILED` transitions during `_finalize_tier3`.
- `test_production_api_key_unconfigured_fails_closed`: Verifies that missing `API_KEY` in production fails closed with HTTP 500.
- `test_audit_query_endpoint_bounded_limits_validation`: Verifies `limit` parameter is strictly validated (`ge=1, le=100`) returning HTTP 422 on boundary violations.
- `test_audit_query_endpoint_nonexistent_scan_returns_404`: Verifies querying audit trail for an unknown scan returns HTTP 404.
- `test_audit_persistence_failure_policy_in_production`: Verifies synchronous scan submission fails closed with HTTP 500 when durable audit repository write fails in production.
- `test_finalize_tier3_unexpected_exception_audited`: Verifies unhandled finalization exception records `SCAN_FAILED` with `UNEXPECTED_FINALIZER_EXCEPTION` and safe metadata.

---

## 5. Changed Files

- `Backend/infrastructure/models.py`: Added `ScanAuditEventDB` model with indexing on `scan_id`, `created_at`, `correlation_id`, `event_type`, `actor_id`, and `tenant_id`.
- `Backend/migrations/versions/0002_scan_audit_trail.py`: Added migration script with reversible `upgrade()` and `downgrade()`.
- `Backend/models/gateway_models.py`: Added `ScanAuditEvent` Pydantic model.
- `Backend/repositories/base.py`: Added `ScanAuditRepository` protocol.
- `Backend/repositories/sql_repositories.py`: Added `SQLScanAuditRepository` implementation.
- `Backend/repositories/in_memory.py`: Added `InMemoryScanAuditRepository` implementation.
- `Backend/repositories/factory.py`: Added `get_scan_audit_repository()`, `set_scan_audit_repository()`, and reset functionality.
- `Backend/repositories/__init__.py`: Exported scan audit repository interfaces and factory methods.
- `Backend/security/audit_logger.py`: Added scan lifecycle enum variants and `log_scan_audit` helper function.
- `Backend/gateway.py`: Instrumented request correlation, actor extraction, audit logging in scan endpoints, background finalization, validation error handler, bounded audit query endpoints, fail-closed production policies, and tenant spoof protection.
- `Backend/tests/test_p1_03_gateway_scan_audit_trail.py`: Comprehensive test suite for P1-03 audit trail (13 tests).
