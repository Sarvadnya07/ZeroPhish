# ZEROphish — Phase 1.11 Architecture Decision: Multi-Worker Gateway State (P1-01) & Shared Rate Limiting (P1-02)

**Status:** ARCHITECTURE DECISION ONLY (PROPOSED)  
**Branch:** `phase1.11/p1-01-p1-02-architecture-discovery`  
**Base Markers:**  
- Phase 1.10 Frozen Baseline: `88943651e5350fd5bb69b883fa52c83bfdc58371`  
- Authoritative Implementation Baseline: `41332b0`  
- P0-01 Runtime Reproducibility: `96e09ccef79c8c7c344b3fc2de26708260eac5e0`  
- P1-07 / P1-08 Test Signal Hardening: `80ad1cb03ba34047c23c5074a5e821b15a29dafe`  
**Authors:** Senior Distributed Systems, Reliability & Application Security Architecture  
**Production Modification Status:** ZERO production source files modified. Strict discovery and decision artifact.

---

## Executive Summary

During Phase 1.10 production readiness evaluation, two architectural findings were logged:
1. **`D-ARCH-2`**: Process-local state versus `workers=4` deployment model.
2. **`D-SEC-1`**: In-memory rate limiter does not provide global enforcement across multiple worker processes.

This document presents a comprehensive, corrected discovery and architectural decision report for:
- **P1-01**: Multi-worker-safe Gateway live state (scan tracking, polling, SSE event fanout).
- **P1-02**: Shared rate-limit storage across multiple workers and replicas.

We establish through verified source inspection that running `Backend/gateway.py` under the declared Docker configuration (`uvicorn --workers 4`) breaks core correctness guarantees when relying on default process-local state (SSE subscriber queues isolated to one worker, scan timing lost, and rate limits inflated $4\times$). 

This refined decision document establishes:
- Accurate concurrency and failure boundaries (distinguishing async I/O concurrency from CPU utilization and process isolation, avoiding invalid GIL-based claims).
- The role of sticky sessions as an optional deployment optimization, **never** an authoritative consistency mechanism.
- A granular **State Ownership Matrix** classifying state objects into `WORKER-LOCAL`, `SHARED-TRANSIENT`, `SHARED-DURABLE`, `OBSERVABILITY`, and `EXECUTION-LOCAL`.
- Clear architectural separation between SQL (durable record), Redis (shared transient transport & counters), and worker memory (socket ownership & task execution).
- Decoupling of distributed circuit-breaker coordination into a separate future reliability initiative.
- Explicit definition of rate-limit outage failure policies as implementation acceptance criteria.
- A staged, zero-regression implementation roadmap sequenced as **P1-01A (Shared Scan Lifecycle)** $\to$ **P1-01B (Cross-Worker SSE)** $\to$ **P1-02 (Global Rate Limiting)**.
- Calibrated scaling assertions that rigorously distinguish `VERIFIED`, `PLANNED`, and `NOT-PROVEN`.

---

## 1. Current Topology

### 1.1 End-to-End Architecture & Topology Diagram

```
                              [ Incoming Client / Browser / Extension Traffic ]
                                                     |
                                                     v
                                         [ Reverse Proxy / Ingress ]
                                      (Round-Robin / Least-Connections)
                                         /           |           \
                                        /            |            \
                                       v             v             v
                              [ Uvicorn W1 ]   [ Uvicorn W2 ]   [ Uvicorn W3 ] ... [ Uvicorn W4 ]
                              +------------+   +------------+   +------------+     +------------+
                              | Memory Lim |   | Memory Lim |   | Memory Lim |     | Memory Lim |
                              | SSE Sockets|   | SSE Sockets|   | SSE Sockets|     | SSE Sockets|
                              | Ckt Breaker|   | Ckt Breaker|   | Ckt Breaker|     | Ckt Breaker|
                              | ScanTracker|   | ScanTracker|   | ScanTracker|     | ScanTracker|
                              | Async Lock |   | Async Lock |   | Async Lock |     | Async Lock |
                              | Exec Tasks |   | Exec Tasks |   | Exec Tasks |     | Exec Tasks |
                              +------------+   +------------+   +------------+     +------------+
                                     |               |                |                  |
                                     \---------------+----------------/------------------/
                                                     |
                                   (Configured: Optional Shared DB)
                                                     v
                                 +---------------------------------------+
                                 |  PostgreSQL / SQLite (DATABASE_URL)   |
                                 |       SQLScanResultRepository         |
                                 +---------------------------------------+
                                 |  (If DATABASE_URL is unset: fallback  |
                                 |   to 4 ISOLATED InMemoryScanResultRepo|
                                 +---------------------------------------+
```

### 1.2 Process-Local Mutable State Inventory (`Backend/gateway.py`)

A rigorous audit of `Backend/gateway.py` identified the following process-local mutable objects:

| State Object | Type | Scope | Lifetime | Synchronization | Failure / Partition Behavior | Security & Correctness Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `limiter` | `slowapi.Limiter(storage_uri="memory://")` | Worker-local | Process lifetime | In-process Python mutex | Memory state reset on worker restart. Counter partitioned across workers. | **D-SEC-1**: Attackers receive $N \times$ configured rate limit across $N$ workers. Non-deterministic throttle enforcement. |
| `_sse_subscribers` | `Dict[str, asyncio.Queue]` | Worker-local | Connection lifetime | Event loop only (asyncio) | If scan runs on Worker A and SSE listener connects to Worker B, Worker B **never receives** scan completion event. | **D-ARCH-2**: Client hangs on SSE connection awaiting completion event; falls back to polling or times out. |
| `_sse_subscriber_overflows` | `int` counter | Worker-local | Process lifetime | Event loop only | Worker-isolated metrics; aggregate overflow metrics cannot be observed. | Reliability observability skew. |
| `scan_started_at` | `BoundedScanTracker` (`collections.OrderedDict`) | Worker-local | Max 10,000 entries / FIFO | Python `threading.Lock` | If scan is started on Worker A, and `/gateway/status/{id}` arrives at Worker B, Worker B has no entry in `scan_started_at`. | Correctness: `estimated_completion_ms` is `None` on Worker B. Inconsistent latency metrics across workers. |
| `scan_results_lock` | `asyncio.Lock` | Worker-local | Process lifetime | Asyncio lock (single event loop) | Protects coroutine concurrency inside **one** process. Zero protection across processes. | Potential race if multiple processes concurrently write or update the same scan entity in shared backend without DB-level row locking. |
| `_background_tasks` | `set[asyncio.Task]` | Worker-local | Task execution | Asyncio event loop | If Worker A crashes or is killed by Uvicorn master, all running Tier 3 background tasks die immediately. | Reliability: Unfinalized scans remain stuck in intermediate state unless an external sweeper or timeout recovers them. |
| `tier3_circuit_breaker` | `CircuitBreaker` | Worker-local | Process lifetime | In-process `asyncio.Lock` | If upstream Tier 3 times out on Worker A, Worker A trips to `OPEN`. Workers B, C, D remain `CLOSED` and continue hammering upstream. | Localized protection only. Circuit breaker trips independently on each worker. |
| `_latest_tier1_report` | `Optional[Dict[str, Any]]` | Worker-local | Process lifetime | Unsynchronized global dict | If `/tier1/report` posts to Worker A, `/tier1/latest` arriving at Worker B returns `None` or stale data. | Stale client telemetry; inconsistent state observable across polling requests. |
| `scan_repo` (when in-memory) | `InMemoryScanResultRepository` | Worker-local | Process lifetime | In-memory dict | Scan written on Worker A is non-existent on Worker B. | Critical functional failure: Polling `/gateway/status/{id}` returns HTTP 404 randomly on 3 out of 4 requests! |
| `cache_backend` (when in-memory) | `InMemoryCacheBackend` | Worker-local | Process lifetime | In-memory dict with TTL | Worker A caches verdict; Worker B performs duplicate upstream analysis. | Redundant external API costs, higher latency, latency jitter. |

---

## 2. Deployment Model Analysis

### 2.1 Artifact Inspection

| Configuration Source | Declared Command / Settings | Evaluated Concurrency Model | Classification |
| :--- | :--- | :--- | :--- |
| `Backend/Dockerfile` (line 65) | `CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]` | Multi-process ($N=4$ workers) | **Declared Configuration** |
| `Backend/Dockerfile.staging` (line 63) | `CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8001"]` | Single-process ($N=1$ worker) | **Declared Configuration** |
| `docker-compose.staging.yml` | Maps backend service to staging Dockerfile, SQLite volume mounted, no Redis service defined. | Single-process, single container | **Verified Deployment Behavior** |
| Operations Runbooks (`docs/` references) | Recommends `--workers 4` for production deployments. | Multi-process ($N=4$ workers) | **Assumed Production Behavior** |
| Production Kubernetes / ECS Manifests | None present in repository. | Unknown replica count | **NOT-PROVEN Behavior** |

### 2.2 Reconciling Verified vs Declared vs Assumed

1. **VERIFIED Deployment Behavior**:
   - Staging operates under a single Uvicorn process (`Dockerfile.staging`).
   - In single-worker mode, in-memory constructs (`limiter`, `_sse_subscribers`, `scan_started_at`, `InMemoryScanResultRepository`) function without cross-worker partitioning bugs.
2. **DECLARED Configuration**:
   - `Backend/Dockerfile` explicitly sets `--workers 4`.
   - `docker-compose.yml` executes this image.
3. **NOT-PROVEN Behavior**:
   - It is NOT PROVEN that the application functions safely under the declared `workers=4` image unless an external shared database (`DATABASE_URL`) is supplied AND clients do not rely on SSE coordination across workers.
   - If `DATABASE_URL` is omitted in a `workers=4` deployment, the gateway is demonstrably broken (returning 404s for 75% of status polls).

---

## 3. Concurrency Rationale: Why Multi-Worker Deployment is Needed

### 3.1 Correct Concurrency Rationale (Correcting GIL Overstatements)

A common misconception is that a single Python process cannot handle concurrent requests due to the Global Interpreter Lock (GIL). **This claim is technically incorrect for asynchronous I/O.**

Under Python's `asyncio` event loop, cooperative multitasking yields execution during network calls (e.g., DNS resolution, HTTP requests, LLM API calls, database queries). A single worker process is capable of handling hundreds or thousands of concurrent I/O-bound connections without being restricted by the GIL.

The justification for a multi-worker deployment in ZeroPhish is **not** an inability of `asyncio` to handle concurrent I/O. Instead, multi-worker architecture is required by the following concrete production factors:

1. **CPU-Bound Execution Bursts**:
   - Tier 1 and Tier 2 execute CPU-intensive feature extraction: lexical URL parsing, entropy calculations, regex evaluation, heuristics, and heuristic tokenization.
   - Vision preprocessing and image decoding execute CPU-heavy image resizing, format normalization, and array operations.
   - In a single-process asyncio loop, intensive CPU work blocks the event loop thread, introducing latency spikes and stalling active I/O coroutines.
2. **Multi-Core Hardware Utilization**:
   - Production instances (e.g. 4-core, 8-core cloud VMs) cannot utilize additional physical CPU cores from a single Python OS process without multiprocessing.
3. **Process-Level Fault Isolation & Crash Resilience**:
   - If an unhandled exception, native C-extension segmentation fault, or out-of-memory (OOM) killer terminates a worker process, the master Uvicorn process respawns that worker while remaining active workers continue serving ingress traffic uninterrupted. In a single-worker model, process death results in total container downtime.
4. **Zero-Downtime Worker Recycling**:
   - Multi-worker master processes support phased worker reloading during deployments or configuration refreshes.

**Conclusion**: Single-worker deployments remain fully viable for local development and lightweight staging. However, production containers require multi-process concurrency to maximize multi-core throughput, absorb CPU-bound bursts, and provide process-level fault isolation.

---

## 4. Sticky Sessions: Deployment Optimization vs Consistency Mechanism

### 4.1 Strict Disqualification of Sticky Sessions for Correctness

It is tempting to consider routing client traffic using "sticky sessions" (session affinity via cookies or IP hashing) as an alternative to shared state.

**Architectural Principle**: **Sticky sessions are an optional load-balancing optimization; they are NOT an authoritative state-consistency mechanism.**

Relying on sticky sessions to guarantee that status polling or SSE connections hit the worker that accepted the initial scan fails under real-world production conditions:

| Production Condition | Behavior Under Sticky Sessions | Consequence if State is Process-Local |
| :--- | :--- | :--- |
| **Worker Process Crash / Recycle** | Uvicorn master routes client to an alternative healthy worker. | Client receives HTTP 404; state lost; stream dead. |
| **Client Reconnection** | Browser or browser extension reconnects after brief network drop, potentially with new IP or stripped headers. | Request routed to different worker; polling fails. |
| **Multiple Extension Clients / Devices** | Multiple client instances or microservices query the same `scan_id`. | Hash/cookie mismatch routes to different workers; inconsistent state. |
| **Container / Pod Rescaling** | Autoscaling adds or removes container replicas, rebalancing ingress hashing buckets. | Session affinity breaks; requests re-routed; 404 spikes. |
| **Load Balancer Proxy Changes** | CDN, Cloudflare, or edge reverse proxies route traffic across diverse backend pools. | Affinity headers not guaranteed across internal hops. |

**Decision**: The ZeroPhish gateway architecture **must remain completely correct without relying on sticky sessions**. State must be observable across workers and replicas by design.

---

## 5. Granular State Ownership Matrix

Rather than treating all state as a single category to "move to Redis," each state object must be classified by its true lifecycle, consistency, and durability requirements:

### Conceptual Categories:
- **`WORKER-LOCAL`**: Process-bound memory, strictly valid only within the executing worker.
- **`SHARED-TRANSIENT`**: Ephemeral, low-latency, cross-worker state where durability across restarts is not required, but cross-worker coordination is mandatory.
- **`SHARED-DURABLE`**: Authoritative system-of-record state requiring ACID persistence across process and container restarts.
- **`OBSERVABILITY`**: Aggregated system metrics, telemetry, and health indicators.
- **`EXECUTION-LOCAL`**: Active Python coroutines and runtime execution handles that cannot be serialized.

### Detailed State Ownership Matrix

| State Object | Current Owner | Current Scope | Required Scope | Durability | TTL | Needs Cross-Worker? | Needs Cross-Replica? | Recommended Category | Recommended Owner | Architectural Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **Completed Scan Result** | `scan_repo` (SQL or InMem) | Local or DB | Global | Persistent | Long-term / Configured | **YES** | **YES** | `SHARED-DURABLE` | PostgreSQL (`SQLScanResultRepository`) | System of record; requires relational queries, history audit, and ACID durability. |
| **Scan Lifecycle Status** | `scan_repo` / Worker Memory | Local or DB | Global | Until Complete + TTL | Windowed / 24h | **YES** | **YES** | `SHARED-DURABLE` | PostgreSQL (`scan_results` table) | Polling clients must deterministically observe status transitions (`PENDING`, `IN_PROGRESS`, `COMPLETED`, `FAILED`). |
| **Scan Start Timing (`scan_started_at`)** | `gateway.py` (`BoundedScanTracker`) | Worker-local | Cluster-wide | Ephemeral | 10–30 min | **YES** | **YES** | `SHARED-TRANSIENT` | Redis string key (`scan:started:<id>`) | High-frequency latency estimation. Does not require DB write overhead; simple TTL auto-pruning. |
| **SSE Connection / Socket Object** | `_sse_subscribers` (`asyncio.Queue`) | Worker-local | Worker-local | Ephemeral | Connection lifetime | **NO** | **NO** | `WORKER-LOCAL` | Worker Memory (`Dict[str, asyncio.Queue]`) | Sockets cannot cross process boundaries. The worker hosting the TCP connection must own the socket queue. |
| **Cross-Worker SSE Event** | Direct function call in Worker A | Worker-local | Cluster-wide | Ephemeral | Immediate / Non-durable | **YES** | **YES** | `SHARED-TRANSIENT` | Redis Pub/Sub (`gateway:scan:events`) | Message transport mechanism. Decouples worker completing scan from worker holding client SSE socket. |
| **Rate-Limit Counters** | SlowAPI `memory://` | Worker-local | Cluster-wide | Ephemeral | Rolling window (e.g. 60s) | **YES** | **YES** | `SHARED-TRANSIENT` | Redis (SlowAPI / `limits` backend) | Sub-millisecond atomic increments (`INCR` + `EXPIRE`). Eliminates $N \times$ rate limit bypass. |
| **Circuit Breaker State** | `CircuitBreaker` | Worker-local | Worker-local (Phase 1.11) | Ephemeral | Rolling window (e.g. 30s) | Deferred | Deferred | `WORKER-LOCAL` | Worker Memory (Phase 1.11 baseline) | **Separated from P1-01/P1-02 scope.** Distributed circuit breakers involve complex failure policies and are deferred to a dedicated reliability pass. |
| **Background Asyncio Tasks** | `_background_tasks` set | Worker-local | Worker-local | Execution | Execution lifetime | **NO** | **NO** | `EXECUTION-LOCAL` | Worker Memory (`set[asyncio.Task]`) | Native coroutines must remain bound to the worker event loop that created them. |
| **Latest Tier-1 Telemetry Report** | `_latest_tier1_report` global | Worker-local | Observability | Ephemeral | Rolling / 5 min | **YES** | Optional | `OBSERVABILITY` | Redis key or Metrics Collector | Telemetry cache. Should not block scan paths. In dev, remains worker-local without affecting scan correctness. |
| **Scan Verdict Cache** | `cache_backend` | Worker or Redis | Cluster-wide | Ephemeral | 24 hours | **YES** | **YES** | `SHARED-TRANSIENT` | Redis (`_RedisCache` in `factory.py`) | Already abstracted in repository layer. Eliminates duplicate upstream LLM/heuristics calls across workers. |

---

## 6. Storage Boundaries: SQL vs Redis vs Worker Memory

To ensure system maintainability and prevent architectural drift, clear boundaries are established:

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

### Architectural Principles:
1. **Redis is NOT a generic database replacement**: Scan records, audit logs, and compliance trails remain strictly in the SQL database.
2. **Redis does NOT own SSE sockets**: TCP sockets, HTTP streams, and `asyncio.Queue` objects remain strictly worker-local. Redis is utilized solely as the **event transport** to fan out events across workers.
3. **Database is NOT a message queue or rate-limiter**: PostgreSQL will not be subjected to high-frequency row locking for rate limiting or polling-based event loops, preserving DB connection pool capacity for business transactions.

---

## 7. Circuit Breaker Scope Separation

**Decision**: Distributed Circuit-Breaker synchronization is **EXCLUDED** from the immediate implementation scope of P1-01 and P1-02.

### Technical Justification:
While `Backend/gateway.py` contains a process-local `CircuitBreaker`, transitioning a circuit breaker from worker-local to distributed across multiple processes introduces non-trivial distributed failure dynamics:
- **Threshold Calibration**: A failure threshold of 5 failures in 30 seconds across 4 workers means either 1.25 failures per worker (over-sensitive) or 20 failures cluster-wide (under-sensitive).
- **False-Positive Blast Radius**: A transient network glitch affecting only Worker 1 could open the breaker globally for Workers 2, 3, and 4, prematurely cutting off healthy upstream traffic.
- **Half-Open Concurrency**: In a distributed half-open state, coordinating which worker executes the single canary probe request requires distributed locking.
- **Provider vs Model Granularity**: Circuit breaking must distinguish between Gemini, OpenAI, and local heuristics.

**Scope Boundary**:
- **P1-01 / P1-02 Scope**: Scan lifecycle state, cross-worker SSE event propagation, and global rate limiting.
- **Future Reliability Milestone**: Distributed Circuit-Breaker coordination, to be evaluated under dedicated fault-injection testing.

---

## 8. Rate-Limit Failure Semantics (Implementation Acceptance Criteria)

In the event of an outage, degradation, or network timeout involving the shared Redis rate-limit store, the gateway must follow strict, security-conscious failure semantics.

Rather than assuming an unverified fail-open policy that could expose external LLM keys to unrestricted abuse, the exact failure semantics are established as **Implementation Acceptance Criteria for P1-02**:

| Failure Mode | Low-Cost / Read Endpoints (`/gateway/status`, `/health`, telemetry) | High-Cost / Mutation Endpoints (`/gateway/scan`, Tier 3 triggers) | Required System Action |
| :--- | :--- | :--- | :--- |
| **1. Redis Healthy** | Strict Rate Enforcement (200 / 429) | Strict Rate Enforcement (200 / 429) | Normal operation. |
| **2. Redis Timeout (>100ms)** | **Fail-Open** (Proceed with request) | **Controlled Degraded / Local Limiter** | Log `RATE_LIMIT_STORE_TIMEOUT`; fallback to process-local backup limiter. |
| **3. Redis Unavailable / Down**| **Fail-Open** (Proceed with request) | **Fail-Closed or Bounded Local Cap** | Log `RATE_LIMIT_STORE_DOWN`; reject or enforce strict emergency local cap. |
| **4. Redis Partially Degraded**| **Fail-Open** | **Controlled Degraded** | Emit alert; limit request concurrency. |
| **5. Atomic Increment Failure** | **Fail-Open** | **Fail-Closed** | Log error; reject scan creation to protect upstream. |
| **6. Expiration / TTL Failure** | Automatic key eviction | Automatic key eviction | Ensure keys use fixed-window fallback if sliding-window script errors. |

**P1-02 Acceptance Requirement**: The P1-02 implementation must explicitly implement and test these failure branches, preventing silent creation of unrestricted provider access paths during infrastructure outages.

---

## 9. Staged Implementation Plan (P1-01A, P1-01B, P1-02)

To minimize blast radius and ensure continuous testability, the implementation is decomposed into three sequential, independently verifiable sub-phases:

```
+------------------------------------------------------------------------------------+
|                         PHASE 1.11 STAGED ROADMAP                                  |
+------------------------------------------------------------------------------------+
|  [P1-01A: Shared Scan Lifecycle]                                                  |
|   - Objective: Cross-worker scan creation, status lookup, and polling              |
|   - Scope: SQLScanResultRepository + Redis scan timing metadata                    |
|   - Proof: 2 & 4 workers; round-robin status polling; zero 404s                    |
+------------------------------------------┬-----------------------------------------+
                                           │ (Verified & Passing)
                                           ▼
+------------------------------------------------------------------------------------+
|  [P1-01B: Cross-Worker SSE Event Fanout]                                          |
|   - Objective: Notify SSE client on Worker B when Tier 3 completes on Worker A     |
|   - Scope: Redis Pub/Sub transport bus; worker-local socket queues                 |
|   - Proof: Subscriber on W1 / completion on W4; reconnect; ordering               |
+------------------------------------------┬-----------------------------------------+
                                           │ (Verified & Passing)
                                           ▼
+------------------------------------------------------------------------------------+
|  [P1-02: Global Shared Rate Limiting]                                              |
|   - Objective: Unified enforcement across all workers and replicas                 |
|   - Scope: SlowAPI / limits Redis storage backend; atomic sliding windows          |
|   - Proof: 2 & 4 workers; uniform & burst traffic; exact limit cutoff; outages     |
+------------------------------------------------------------------------------------+
```

### Detailed Phase Specifications

#### P1-01A — Shared Scan Lifecycle
- **Objective**: A scan created by Worker A must have consistently observable lifecycle state when queried from Worker B, C, or D.
- **Authoritative State Owner**: `SQLScanResultRepository` (PostgreSQL in production, SQLite in local dev) for scan records; Redis for `scan_started_at` latency estimation metadata.
- **Required Verification**:
  - 2-worker and 4-worker Uvicorn test harnesses.
  - Creation on Worker A followed by immediate polling on Worker B.
  - Verification that `estimated_completion_ms` is valid across all workers.
  - Worker restart during pending scan.

#### P1-01B — Cross-Worker SSE Event Fanout
- **Objective**: A worker completing Tier 3 analysis must broadcast completion events across all active workers holding client SSE connections.
- **Conceptual Architecture**:
  ```
  Worker A (Executes Tier 3)
      │ (Publishes completion event)
      ▼
  Redis Pub/Sub Topic: "gateway:scan:events"
      │ (Fans out to subscribed worker processes)
      ▼
  Worker B (Hosts client TCP connection)
      │ (Pushes event to client's asyncio.Queue)
      ▼
  Client EventSource
  ```
- **Required Verification**:
  - SSE client connected to Worker 1 receives completion event when scan runs on Worker 4.
  - Clean client disconnect and connection cleanup.
  - Event deduplication and delivery ordering.

#### P1-02 — Global Shared Rate Limiting
- **Objective**: Eliminate the $N \times$ rate limit multiplication defect across workers.
- **Conceptual Architecture**:
  ```
  Worker A ──┐
  Worker B ──┤
  Worker C ──┼──▶ Shared Redis Limiter (Atomic INCR / Sliding Window)
  Worker D ──┘
  ```
- **Required Verification**:
  - 2-worker and 4-worker tests under uniform round-robin traffic.
  - Strict limit cutoff (e.g. 10 requests allowed, 11th request receives HTTP 429 across 4 workers).
  - Outage simulation verifying fail-closed / degraded behavior for scan submissions.

---

## 10. Runtime Contracts: Production vs Local Development

To ensure local developer velocity without compromising production rigor, two formal runtime contracts are defined:

### 10.1 Production Runtime Contract
- **Durable State**: `DATABASE_URL` is mandatory (PostgreSQL).
- **Transient Coordination**: `REDIS_URL` is mandatory.
- **Concurrency**: `uvicorn --workers 4` (or configured container count).
- **Contract Guarantee**: Multi-worker and multi-process safe. No accidental in-memory fallback pretending to be distributed-safe. If `REDIS_URL` is missing in production mode, startup fails with an explicit configuration error.

### 10.2 Local Development Runtime Contract
- **Durable State**: SQLite file or in-memory database supported.
- **Transient Coordination**: In-memory state coordinators supported when `REDIS_URL` is omitted.
- **Concurrency**: **Explicitly constrained to single-process execution** (`uvicorn --workers 1`).
- **Contract Guarantee**: Clean, zero-external-dependency local development. The local fallback is formally scoped as **SINGLE-PROCESS ONLY** and must never be documented or deployed as multi-worker safe.

---

## 11. Scaling Boundary Claims (Calibration Audit)

In compliance with architectural honesty, horizontal scaling boundaries are formally classified:

| Scaling Boundary | Status | Technical Evidence & Current Justification |
| :--- | :--- | :--- |
| **Multi-Worker Safety (Single Container)** | **PLANNED (Target of P1-01/P1-02)** | Validated by architecture design; will be verified upon completion of P1-01 and P1-02 test suites. Currently **NOT-PROVEN** on `main`. |
| **Multi-Container Safety (Same Host)** | **PLANNED** | Shares identical semantics with multi-worker when connected to external DB and Redis. Target of Phase 1.11 staging verification. |
| **Multi-Replica Safety (Cluster / K8s)** | **NOT-PROVEN** | Requires distributed ingress, healthcheck tuning, clock synchronization, and cluster network policies. Not verified in repository. |
| **Multi-Region Safety** | **NOT-PROVEN / OUT OF SCOPE** | Cross-region latency, split-brain resolution, and active-active database replication are not designed or supported. |

---

## 12. Pre-Implementation Test Strategy & Matrix

Before implementation begins, the test strategy must establish rigorous validation criteria across four distinct testing tiers:

```
+-----------------------------------------------------------------------------------+
|                            PHASE 1.11 TEST MATRIX                                |
+----+---------------------------------------+---------------------+----------------+
| #  | Test Class                            | Execution Mode      | Test Tier      |
+----+---------------------------------------+---------------------+----------------+
| 1  | Local Single-Worker Baseline          | In-Memory / SQLite  | DETERMINISTIC  |
| 2  | Two-Worker Scan State Visibility      | Multi-process / DB  | DETERMINISTIC  |
| 3  | Four-Worker Scan State Visibility     | Multi-process / DB  | DETERMINISTIC  |
| 4  | Worker Termination / Kill Recovery    | Subprocess SIGKILL  | INTEGRATION    |
| 5  | Bounded State Expiry & Pruning        | Time-mock / Unit    | DETERMINISTIC  |
| 6  | Concurrent Scan Submissions           | Multi-client burst  | STRESS         |
| 7  | Cross-Worker Polling (Round-Robin)    | 4 Uvicorn Workers   | INTEGRATION    |
| 8  | Cross-Worker SSE Fanout               | Pub/Sub Multi-Worker| INTEGRATION    |
| 9  | Multi-Worker Rate-Limit Enforcement   | 4 Workers Uniform   | DETERMINISTIC  |
| 10 | Concurrent Rate-Limit Increments      | Parallel Bursts     | STRESS / RACE  |
| 11 | Shared-State (Redis) Outage Injection | Fault Injection     | INTEGRATION    |
| 12 | Redis Reconnection & Recovery         | Fault Recovery      | INTEGRATION    |
+----+---------------------------------------+---------------------+----------------+
```

### Clarification on Test Tiers:
- **DETERMINISTIC TEST**: Mathematical assertion of state equality and exact status code transitions.
- **INTEGRATION TEST**: Multi-process end-to-end flow validation across network sockets.
- **STRESS TEST**: High-concurrency load testing to detect race conditions under load.
- *Note:* Stress and randomized property testing provide empirical evidence under specific loads, not formal mathematical proofs of correctness.

---

## 13. Final Architecture Recommendation

**Recommendation**: **Hybrid Shared-State Architecture**
- **Durable State**: PostgreSQL via `SQLScanResultRepository` for scan records, results, and audit trails.
- **Transient Coordination**: Redis for rate limiting (P1-02), cross-worker SSE Pub/Sub transport (P1-01B), and scan latency timing (P1-01A).
- **Worker Memory**: TCP sockets, connection queues, active `asyncio.Task` handles, and worker-local circuit breakers.
- **Local Dev**: Explicit single-worker in-memory fallback.

---

## 14. Phase 1.10 Freeze Integrity

- **Frozen Marker**: `88943651e5350fd5bb69b883fa52c83bfdc58371`
- **Authoritative Baseline**: `41332b0`
- **Branch**: `phase1.11/p1-01-p1-02-architecture-discovery`
- **Integrity Status**:
  - `docs/PHASE_1_FINAL_PRODUCTION_READINESS_REPORT.md` is strictly unmodified.
  - Branch `main` is strictly unmodified.
  - Zero production application files have been modified.
  - Documentation-only change scope maintained.
