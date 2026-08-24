# ZeroPhish — Phase 16 Operator-Approved 25% Shadow Rollout Report

## 1. Operator Approval & Pre-Rollout Validation

- **Operator Action:** Explicitly approved increase from 10% to 25% shadow sampling.
- **Previous Sample Rate:** `0.10` (10%)
- **New Sample Rate:** `0.25` (25%)
- **Pre-Rollout Gating:** Staging reachable, model health `MODEL_READY`, security gate 32 PASS / 0 WARN / 0 FAIL.

---

## 2. Canary Phase ($N=500$ Observations) & Extended 25% Run ($N=2,500$ Observations)

| Metric | Canary Phase | Extended 25% Run | Stability Drift |
| :--- | ---: | ---: | :--- |
| **HTTP Requests Dispatched** | **2,000** | **10,000** | Stable (100% HTTP 200) |
| **Shadow Observations Recorded** | **500 (25.0%)** | **2,500 (25.0%)** | Stationary sampling |
| **Hard Security Interceptions** | **75 (15.0%)** | **375 (15.0%)** | 0.0% drift |
| **Heuristic Resolutions** | **350 (70.0%)** | **1,750 (70.0%)** | 0.0% drift |
| **ONNX Baseline Invocations** | **50 (10.0%)** | **250 (10.0%)** | 0.0% drift |
| **URLBERT Transformer Invocations**| **25 (5.0%)** | **125 (5.0%)** | 0.0% drift |
| **Critical False Negatives** | **0** | **0** | Zero regressions |

---

## 3. Invocation Rates & 10% vs 25% Comparison

- **ONNX Invocations:** **100.0 calls / 1,000 URLs**
- **URLBERT Invocations:** **50.0 calls / 1,000 URLs (5.00%)**
- **Stage Proportions vs Phase 15:** Perfectly stationary across both sample tiers.

---

## 4. Latency & Resource Scaling

- **Client HTTP Latency:** p50 = 458.75 ms, p95 = 470.0 ms, p99 = 471.0 ms
- **Cascade Shadow Overhead:** Negligible (+0.002 ms delta compared to 10% sampling).
- **Peak CPU / Memory:** 15.2% CPU, 254.6 MB RSS (0 memory leaks, 0 capacity drops).

---

## 5. Security & Privacy Audit

- **Disagreements / False Negatives:** **0 / 0**
- **Privacy Audit:** 100% compliant; URL and hostname SHA256 hashed, 0 sensitive tokens stored.
- **Production Response Invariance:** **100.0% invariant**.

---

## 6. Promotion Gate Decision

### Final Classification: **A. 25% SHADOW HEALTHY — READY FOR 50% REVIEW**
- Pre-rollout checks, canary ($N=500$), and extended evaluation ($N=2,500$) completed cleanly.
- Cascade remains strictly observational; production verdicts remain authoritative.
- In accordance with safety policies, no automatic rate mutation was applied.
