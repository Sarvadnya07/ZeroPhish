# ZeroPhish — Phase 13.2 Controlled Staging Traffic Evaluation Report

## 1. Workload Parameters & Provenance

- **Traffic Classification:** `CONTROLLED_STAGING` (Safe staging URL vectors)
- **Workload Version:** `v1.0.0`
- **Generator Run ID:** `gen_run_38f1ed7d7a28`
- **Total Requests Dispatched:** **20**
- **Dispatched Rate:** `100.0 req/sec`

---

## 2. Stage Distribution & Model Invocation ($N=20$)

- **Hard-Rule Resolutions:** **0.0%** (SSRF / RFC1918 vectors)
- **Heuristic Resolutions:** **100.0%**
- **ONNX Invocations:** **0.00%**
- **URLBERT Invocations:** **0.00%**
- **Disagreements / Potential FNs:** **0 / 0**

---

## 3. End-to-End API Latency Profile

| Metric | Client HTTP Latency | Server Cascade Shadow | User Response Delta |
| :--- | ---: | ---: | :--- |
| **p50 Latency** | **4.565 ms** | **0.021 ms** | **+0.001 ms** |
| **p95 Latency** | **5.849 ms** | **0.200 ms** | **+0.001 ms** |
| **p99 Latency** | **7.207 ms** | **15.050 ms** | **+0.001 ms** |

---

## 4. Promotion Gate Assessment

### Status: **A. CONTROLLED STAGING TRAFFIC VERIFIED**
- **Observations Recorded:** **20 / 20 (100% complete)**
- **Response Invariance:** **100.0%**
- **Sample Rate:** **Maintained at 10% shadow** (No automatic promotion).
