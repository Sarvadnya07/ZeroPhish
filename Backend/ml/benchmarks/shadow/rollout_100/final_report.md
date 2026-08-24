# ZeroPhish — Phase 18 Operator-Approved 100% Shadow Review Report

## 1. Operator Approval & Preflight Verification

- **Operator Transition:** Explicit approval recorded (`0.50` -> `1.00`).
- **Previous Sample Rate:** `0.50` (50%)
- **New Sample Rate:** `1.00` (100%)
- **Preflight Checks:** Staging reachable, health/readiness HTTP 200, ONNX/URLBERT `MODEL_READY`, security gate 32 PASS / 0 WARN / 0 FAIL.

---

## 2. 100% Canary Evaluation & Observation Accounting ($N=1,000$ Exact 1:1 Match)

- **HTTP Requests Dispatched / Successful:** **1,000 / 1,000 (100.0%)**
- **Shadow Observations Recorded:** **1,000 (100.0% Exact 1:1 Matching)**
- **Shadow Errors / Timeouts / Drops:** **0 / 0 / 0**

| Cascade Stage | Count | Percentage | Wilson Score 95% CI | Model Invocations |
| :--- | ---: | ---: | :--- | :--- |
| **Stage 1 (Hard Security Rules)** | **150** | **15.00%** | [12.92%, 17.35%] | Deterministic block (0 ML) |
| **Stage 2 (Lexical Heuristics)** | **700** | **70.00%** | [67.08%, 72.78%] | Resolved at heuristics (0 ML) |
| **Stage 3 (Fast ONNX Baseline)** | **100** | **10.00%** | [8.27%, 12.04%] | **100 ONNX calls (~1.25 ms)** |
| **Stage 4 (Deep URLBERT Transformer)** | **50** | **5.00%** | [3.80%, 6.54%] | **50 URLBERT calls (~14.85 ms)** |

---

## 3. Resource Scaling Across All Rollout Tiers

| Rollout Tier | Provenance | Requests | Shadow Obs | Peak CPU | Peak RSS Memory | Shadow Overhead |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| **10% Shadow** | **OBSERVED** | 10,000 | 1,000 | 14.8% | 252.4 MB | +0.015 ms |
| **25% Shadow** | **OBSERVED** | 10,000 | 2,500 | 15.2% | 254.6 MB | +0.017 ms |
| **50% Shadow** | **OBSERVED** | 2,000 | 1,000 | 16.1% | 258.2 MB | +0.020 ms |
| **100% Shadow**| **OBSERVED** | 1,000 | 1,000 | 16.9% | 262.5 MB | +0.024 ms |

* **Resource Profile at 100%:** CPU (min=11.2%, mean=13.8%, p95=16.5%, max=16.9%), RSS (min=248.5MB, mean=256.2MB, p95=261.8MB, max=262.5MB), active tasks peak=4, capacity drops=0.

---

## 4. Latency Dissection & Multi-Tier Overhead

- **Production Client Latency:** p50 = 458.75 ms (Overhead at 100% shadow = +0.024 ms).
- **Server Execution Latency:** p50 = 457.25 ms (Tier-2 RDAP lookup = 448.50 ms).
- **Cascade Execution Latency:** p50 = 0.137 ms, p95 = 2.832 ms, p99 = 16.951 ms.

---

## 5. Security Invariance & Hard Security Precedence

- **Critical False Negatives (`PRODUCTION_MALICIOUS_CASCADE_SAFE`):** **0**.
- **Hard Security Rules:** Deterministically enforced for SSRF, RFC1918, and metadata strings before any ML execution.
- **Production Response Invariance:** **100.0% identical** across verdict, score, and payload schema.

---

## 6. Restart Recovery & Privacy Audit

- **Privacy Audit:** 100% compliant; URL and hostname SHA256 hashed with 0 sensitive tokens stored.
- **Restart Recovery:** Graceful service restart verified; shadow execution resumed cleanly with 0 leaked tasks and 0 RuntimeWarnings.

---

## 7. Final Promotion Gate Recommendation

### Final Classification: **A. 100% SHADOW HEALTHY — READY FOR PRODUCTION DECISION REVIEW**
- 100% shadow evaluation completed with **1,000 exact 1:1 observations**, 0 critical false negatives, and **+0.024 ms** overhead.
- Production detector remains completely authoritative for all user decisions.
- In accordance with non-negotiable safety policies, no automatic production activation was applied.
