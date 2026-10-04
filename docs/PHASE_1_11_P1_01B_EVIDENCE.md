# ZERO PHISH — PHASE 1.11 / P1-01B EVIDENCE
## Cross-Worker Server-Sent Events (SSE) Event Propagation

**Date**: 2026-10-04  
**Author**: Antigravity  
**Task**: P1-01B — Cross-Worker SSE Event Propagation  
**Branch**: `phase1.11/p1-01b-cross-worker-sse`  
**Base Commit**: `ffdfdf0`  

---

### 1. Problem Statement & Background
Prior to P1-01B, ZeroPhish Gateway maintained Server-Sent Events (SSE) subscriber queues strictly in process-local memory (`Dict[str, asyncio.Queue]`). When running across multiple workers (e.g. Uvicorn with multiple workers or multiple replicas):
- If a client connected its SSE EventSource to **Worker B**, but a scan was processed or completed by **Worker A**, the scan lifecycle event remained locked inside Worker A.
- Worker B never received or forwarded the event to the client's socket queue, breaking live dashboard updates in multi-process architectures.

### 2. Implemented Architecture
In strict adherence to the approved Phase 1.11 Architecture Decision (`docs/PHASE_1_11_P1_01_P1_02_ARCHITECTURE_DECISION.md`):

```
+-----------------------------------------------------------------------------------------+
|                                    STORAGE BOUNDARIES                                   |
+--------------------------------+--------------------------------+-----------------------+
| SQL / Database (PostgreSQL)    | Redis (Shared Transient)       | Worker Process Memory |
| Authoritative Durable State    | Ephemeral Coordination         | Socket & Execution    |
+--------------------------------+--------------------------------+-----------------------+
| - Completed scan records       | - Rate-limiting counters       | - Live SSE TCP sockets|
| - Scan status transitions      | - Sliding-window timestamps    | - Local asyncio.Queue |
| - Security audit trails        | - SSE Pub/Sub event transport  | - Active Task handles |
| - Threat telemetry persistence | - Scan start timing (TTL keys) | - In-memory buffer    |
| - Tenant configurations        | - Shared scan verdict cache    | - Local circuit breaker|
+--------------------------------+--------------------------------+-----------------------+
```

#### Event Transport Bus:
- **Redis Channel**: `gateway:scan:events`
- **Origin Worker Tagging**: Each process assigns an immutable `WORKER_ID = str(uuid.uuid4())`.
- **Event Envelope**:
  ```json
  {
    "event_id": "<uuid>",
    "origin_worker": "<origin_uuid>",
    "event_type": "scan_update",
    "data": { ... }
  }
  ```

#### Flow:
1. **Local Emission**: When a scan creates or updates a report on Worker A (`_broadcast_to_subscribers(payload, propagate=True)`), the event is delivered to any local subscribers on Worker A and asynchronously published to `gateway:scan:events` via `_publish_cross_worker_sse`.
2. **Remote Reception**: Worker B's worker-level listener loop (`_sse_redis_listener_loop`) consumes the event from Redis Pub/Sub:
   - Validates envelope structure and payload integrity.
   - Filters out self-originated events (`origin_worker == WORKER_ID`) to prevent echo amplification.
   - Validates uniqueness via an in-memory sliding seen-events buffer (`MAX_SEEN_EVENTS = 1000`) for deduplication.
   - Fans out to Worker B's local connected subscribers with `propagate=False` (preventing infinite republish loops).
   - Updates `_latest_tier1_report` for dashboard refreshes on Worker B.

### 3. Production Contract & Local Development
- **Production Mode (`CONFIG.env == "production"`)**:
  - Requires `DATABASE_URL` (authoritative persistence) AND `REDIS_URL` (cross-worker event propagation).
  - Lifespan fails closed with an explicit, actionable error if `REDIS_URL` is absent:
    `RuntimeError("REDIS_URL must be configured in production environment for multi-worker SSE event propagation.")`
- **Local Development Mode (`CONFIG.env != "production"`)**:
  - If `REDIS_URL` is absent, the gateway runs in transparent local-only fallback mode without raising exceptions.
  - Health endpoint reports `"sse": {"pubsub_active": false}`.
  - Readiness probe reports `"dependencies": {"redis_pubsub": "local-only"}`.

### 4. Lifecycle & Resource Safety
- **Clean Shutdown**: `lifespan` cancellation in `stop_sse_pubsub()` cancels the background listener task, unsubscribes from `gateway:scan:events`, closes Redis asynchronous connections via `aclose()`, and clears subscriber registries.
- **Connection Leak Prevention**: Background tasks are tracked in `_background_tasks` with done-callbacks, preventing unhandled garbage collection or orphaned coroutines.

### 5. Verification Test Matrix
The test suite `Backend/tests/test_p1_01b_sse_cross_worker.py` deterministically validates all matrix requirements:

| Test ID | Test Name | Result |
| :--- | :--- | :--- |
| **Test 1** | Same-worker SSE regression | **PASSED** |
| **Test 2** | Cross-worker delivery (Worker A -> Redis -> Worker B -> Subscriber) | **PASSED** |
| **Test 3** | Multiple workers topology (4 workers fanout) | **PASSED** |
| **Test 4** | Worker restart & clean re-subscription | **PASSED** |
| **Test 5** | Client reconnect semantics (stateless reconnect, no replay expectation) | **PASSED** |
| **Test 6** | Duplicate event injection & deduplication | **PASSED** |
| **Test 7** | Event ordering preservation across multiple scan phases | **PASSED** |
| **Test 8** | Cleanup and background task leak prevention on shutdown | **PASSED** |
| **Test 9** | Production configuration contract fail-closed check | **PASSED** |
| **Test 10**| Loop prevention (self-originated events ignored) | **PASSED** |
| **Test 11**| Independent OS multi-process cross-worker SSE propagation harness | **PASSED** |

### 6. Scope Boundaries & Explicit NOT-PROVEN Items
- **P1-02 Distributed Rate Limiting**: NOT implemented. SlowAPI configuration untouched.
- **Distributed Circuit Breakers**: NOT implemented. Circuit breaker remains worker-local as decided in architecture doc Section 7.
- **Scan Lifecycle Durability**: Preserved intact from P1-01A. PostgreSQL/SQLite remains the single authoritative durable record store.
- **Redis Durability / Replay**: Redis Pub/Sub is explicitly transient. No claim of durable event queuing or historical message replay is made. Clients reconnecting to SSE rely on the authoritative REST endpoints (`/api/v1/scan/{id}`, `/gateway/result/{id}`).
