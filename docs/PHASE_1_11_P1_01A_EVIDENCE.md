# P1-01A Evidence

## Objective

The objective of P1-01A is to establish an authoritative shared scan lifecycle for multi-worker execution, eliminating correctness dependencies on worker-local process memory for scan state, completion status, and lifecycle queries.

## Existing Lifecycle Problem

Prior to P1-01A, multi-worker deployments suffered from worker-local memory isolation:
1. `scan_started_at`: Stored in a process-local `BoundedScanTracker` dict (`gateway.py:389`). If Worker A received a scan submission and Worker B handled `/gateway/status/{scan_id}`, Worker B had no record in its local memory dictionary. Consequently, `estimated_completion_ms` evaluated to `None` on Worker B, causing divergent client polling behavior.
2. `_finalize_tier3`: Elapsed execution time calculation (`total_ms`) looked only at `scan_started_at[scan_id]`. If finalized in a recovered or separate execution context, `total_ms` was discarded or unavailable.
3. Concurrency Overwrite Hazard: An out-of-order partial scan update (`complete=False`) could overwrite an already completed scan (`complete=True`), regressing the authoritative verdict and completion status in both relational and in-memory repositories.
4. Production Fallback Hazard: If `DATABASE_URL` was absent in production, workers could operate with process-local state without an upfront fatal startup check during application lifespan initialization.

## Implementation

1. **Authoritative SQL Lifecycle Persistence (`SQLScanResultRepository.save`)**:
   - Enforced strict concurrency guard: if `existing.complete` is `True` and incoming `complete` is `False`, the stale write is safely rejected and logged.
   - Monotonic layer progression: `existing.layers_completed = max(existing.layers_completed, layers_completed)`.
2. **In-Memory Adapter Parity (`InMemoryScanResultRepository.save`)**:
   - Implemented identical stale-overwrite protection under repository mutex lock.
3. **Cross-Worker Timing Resolution (`gateway.py`)**:
   - In `gateway_status`: If `scan_started_at.get(scan_id)` is not in local process memory (e.g. status polled by Worker B), the endpoint falls back to `result.timestamp` from the durable record: `(datetime.now(timezone.utc) - result.timestamp).total_seconds() * 1000`, computing consistent `estimated_completion_ms` across any worker.
   - In `_finalize_tier3`: Added identical fallback to `existing.timestamp` for `total_execution_time_ms`.
4. **Production Runtime Contract (`gateway.py:lifespan`)**:
   - Verified that `lifespan` strictly enforces `CONFIG.env == "production"` requires `DATABASE_URL`, failing closed immediately with a `RuntimeError` before accepting traffic.

## Authoritative State

The authoritative scan lifecycle state is owned exclusively by PostgreSQL / the SQL repository abstraction (`ScanResultDB` table `scan_results`):
- `scan_id`: Unique primary key identifier (`VARCHAR(64)`).
- `timestamp`: UTC creation timestamp (`DATETIME`).
- `partial_score`: Float baseline score from early layers.
- `final_score`: Float fused score upon scan completion (`NULL` while in-flight).
- `verdict`: Current canonical verdict string (`SAFE`, `SUSPICIOUS`, `CRITICAL`).
- `complete`: Boolean completion flag (`0` in-flight, `1` complete).
- `layers_completed`: Monotonically increasing completed tier count.
- `data_json`: Canonical JSON serialized `GatewayScanResponse`.
- `created_at`: Epoch timestamp for indexing and ordering.

Transient worker state (SSE queues, active asyncio tasks, in-memory timing caches) remains worker-local and non-authoritative.

## Local Development Contract

- In local development (`ZEROPHISH_ENV != "production"`), single-process in-memory (`InMemoryScanResultRepository`) and SQLite fallback remain fully functional without requiring external database services.
- The development contract preserves identical repository interfaces (`ScanResultRepository` protocol) and stale-overwrite protection.

## Production Contract

- In production (`ZEROPHISH_ENV == "production"`), durable relational persistence via `DATABASE_URL` is mandatory.
- If `DATABASE_URL` is omitted, the application fails closed during the lifespan startup probe with:
  `RuntimeError: DATABASE_URL must be configured in production environment for multi-worker safety.`
- Multi-worker deployments read and write authoritative lifecycle state through PostgreSQL / SQLAlchemy pooled connection sessions.

## Concurrency Model

- **Stale Overwrite Protection**: A completed scan record (`complete=True`) cannot be overwritten by an incomplete update (`complete=False`).
- **Monotonic Progression**: `layers_completed` is guaranteed non-decreasing (`max(existing.layers_completed, layers_completed)`).
- **Session Transactions**: Every SQL repository mutation is wrapped in a session transaction context manager with explicit `commit()` and `rollback()` on failure.

## Tests

The dedicated test suite `Backend/tests/test_p1_01a_lifecycle.py` validates the complete shared lifecycle behavior across 11 deterministic tests:

### Same Worker
- `test_same_worker_lifecycle`: Exercises scan creation, in-progress retrieval (`complete=False`), completion (`complete=True`, `final_score=85.0`, `CRITICAL`), and verified status retrieval.

### Cross Worker
- `test_cross_worker_lifecycle`: Worker A creates in-progress scan in shared SQLite file, Worker B retrieves status without Worker A memory context, Worker A completes scan, Worker B immediately observes completed state.
- `test_cross_worker_estimated_completion_calculation`: Worker B (with zero `scan_started_at` in-memory state) calculates valid `estimated_completion_ms` using the durable record timestamp.

### Restart Boundary
- `test_restart_boundary_preserves_state`: Worker A creates scan, engine and session factory are completely disposed (`del repo1`, `del factory1`), new engine and factory initialize in fresh context, verifying durable state recovery.

### Failure
- `test_persistence_failure_raises_and_does_not_mask_as_safe`: Database write failure triggers transaction rollback, raises `RuntimeError`, and ensures unpersisted or corrupted scans never default to `SAFE`.
- `test_production_persistence_contract_lifespan`: Validates fail-closed startup behavior when `env="production"` and `DATABASE_URL` is missing.

### Expiry
- `test_expiry_and_count_semantics`: Verifies `count()`, `count_pending()`, `list_all()`, and `delete()` methods.

### Concurrency
- `test_stale_incomplete_update_does_not_overwrite_complete_sql`: Verifies that attempting to write an incomplete record over a complete record in `SQLScanResultRepository` preserves the completed state.
- `test_stale_incomplete_update_does_not_overwrite_complete_in_memory`: Verifies identical guard behavior in `InMemoryScanResultRepository`.

### Multi-Worker Integration Harness
- `test_multi_worker_2_processes`: Spawns 2 distinct OS processes (`multiprocessing.Process`), verifying Worker A write $\to$ Worker B read $\to$ Worker A complete $\to$ Worker B read without shared memory.
- `test_multi_worker_4_processes`: Spawns 4 distinct OS processes (1 writer, 3 concurrent readers), verifying synchronized cross-process state visibility across all worker nodes.

## Results

- `Backend/tests/test_p1_01a_lifecycle.py`: **11 passed in 28.26s**
- Combined reliability regression (`test_p1_01a_lifecycle.py`, `test_completion_gaps.py`, `test_p1_reliability.py`, `test_repositories.py`): **37 passed in 35.47s**

## Security Review

- **Access Control & Authorization**: Preserved `verify_api_key` dependency on status and result endpoints; no IDOR vulnerabilities or unauthenticated exposure introduced.
- **Fail-Closed Persistence**: Database failures immediately raise and rollback transactions, preventing silent fallbacks or accidental `SAFE` verdicts.
- **Input Sanitization**: Unchanged; existing `InputValidator` and payload constraints remain authoritative.

## Phase 1.10 Freeze Integrity

- Frozen baseline marker `88943651e5350fd5bb69b883fa52c83bfdc58371` is completely untouched.
- `docs/PHASE_1_FINAL_PRODUCTION_READINESS_REPORT.md` has NOT been modified.
- No changes made to `main` branch.

## NOT-PROVEN

The following items are outside the boundary of P1-01A and are explicitly NOT PROVEN by this change:
- **P1-01B (Cross-Worker SSE Pub/Sub)**: NOT IMPLEMENTED. SSE broadcast remains worker-local in this phase.
- **P1-02 (Distributed Rate Limiting)**: NOT IMPLEMENTED. Rate limiting currently relies on worker-local SlowAPI limiter state.
- **Distributed Circuit Breaker**: NOT IMPLEMENTED. Circuit breakers remain local to individual worker processes.
- **Multi-region active-active database replication**: Untested and outside scope.
