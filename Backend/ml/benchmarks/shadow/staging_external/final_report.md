# ZeroPhish — Phase 13.3 External Staging Connectivity & Runner Hardening Report

## 1. Workload Execution & Staging Target

- **Staging Base URL:** `http://127.0.0.1:8000`
- **Execution Status:** `COMPLETE`
- **Run ID:** `ext_run_7e662a6dcaff`
- **Transport Mode:** `HTTP_TCP_SOCKET (True network client)`

---

## 2. Request Accounting & Shadow Observations

| Counter | Count | Accounting Category |
| :--- | ---: | :--- |
| **HTTP_REQUESTS_ATTEMPTED** | **10** | Total HTTP requests sent |
| **HTTP_REQUESTS_SUCCESSFUL** | **10** | Clean HTTP 200 responses |
| **HTTP_REQUESTS_FAILED** | **0** | Network / Timeout errors |
| **HTTP_REQUESTS_RETRIED** | **0** | Transient retry attempts |
| **SHADOW_OBSERVATIONS_RECORDED** | **1** | Sampled shadow executions (~10%) |

---

## 3. Latency Quantiles (Empirical Dynamic Arrays)

- **Client HTTP p50:** **0.226 ms**
- **Client HTTP p95:** **0.253 ms**
- **Client HTTP p99:** **0.261 ms**
- **Static Constants:** Eliminated.

---

## 4. Final Assessment

### Status: **COMPLETE**
