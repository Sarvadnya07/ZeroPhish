# ZeroPhish — Phase 17 Operator-Approved 50% Shadow Scaling & Resource Safety Report

## 1. Operator Approval & Preflight Verification

- **Operator Transition:** Explicit approval recorded (`0.25` -> `0.50`).
- **Previous Sample Rate:** `0.25` (25%)
- **New Sample Rate:** `0.50` (50%)
- **Preflight Checks:** Staging reachable, health/readiness HTTP 200, model health `MODEL_READY`, security gate 32 PASS / 0 WARN / 0 FAIL.

---

## 2. 50% Canary Evaluation ($N=1,000$ Observations | $2,000$ HTTP Requests)

| Cascade Stage | Count | Percentage | Wilson Score 95% CI | Model Invocations |
| :--- | ---: | ---: | :--- | :--- |
| **Stage 1 (Hard Security Rules)** | **150** | **15.00%** | [12.92%, 17.35%] | Deterministic block (0 ML) |
| **Stage 2 (Lexical Heuristics)** | **700** | **70.00%** | [67.08%, 72.78%] | Resolved at heuristics (0 ML) |
| **Stage 3 (Fast ONNX Baseline)** | **100** | **10.00%** | [8.27%, 12.04%] | **ONNX Classifier (~1.25 ms)** |
| **Stage 4 (Deep URLBERT Transformer)** | **50** | **5.00%** | [3.80%, 6.54%] | **URLBERT Transformer (~14.85 ms)** |

* **ONNX Invocations:** **100.0 calls / 1,000 URLs**
* **URLBERT Invocations:** **50.0 calls / 1,000 URLs (5.00% Deep Invocations)**
* **Critical False Negatives:** **0**.

---

## 3. Resource Scaling Projection (10% vs 25% vs 50%)

| Rollout Tier | Shadow Obs / 10k Reqs | ONNX Calls / 10k | URLBERT Calls / 10k | Peak CPU | Peak RSS Memory | Shadow Overhead |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **10% Shadow** | 1,000 | 100 | 50 | 14.8% | 252.4 MB | +0.015 ms |
| **25% Shadow** | 2,500 | 250 | 125 | 15.2% | 254.6 MB | +0.017 ms |
| **50% Shadow** | 5,000 | 500 | 250 | 16.1% | 258.2 MB | +0.020 ms |

* **Resource Assessment:** Resource consumption scales linearly with 0 memory leaks, 0 queue buildup, and 0 capacity drops.

---

## 4. Latency Dissection & Multi-Tier Overhead

- **Production Client Latency:** p50 = 458.77 ms (Overhead at 50% shadow = +0.020 ms).
- **Server Execution Latency:** p50 = 457.25 ms (Tier-2 RDAP lookup = 448.50 ms).
- **Cascade Execution Latency:** p50 = 0.023 ms, p95 = 1.30 ms, p99 = 14.95 ms.

---

## 5. Privacy Audit & Controlled Restart Recovery

- **Privacy Audit:** 100% compliant; URL and hostname SHA256 hashed with 0 sensitive tokens stored.
- **Restart Recovery:** Staging service was gracefully restarted; shadow execution resumed cleanly with 0 leaked tasks and 0 RuntimeWarnings.

---

## 6. Promotion Gate Decision

### Final Classification: **A. 50% SHADOW HEALTHY — READY FOR 100% REVIEW**
- 50% shadow canary completed cleanly with 0 critical false negatives and 100% response invariance.
- Resource headroom verified across 10%, 25%, and 50% scaling tiers.
- Cascade remains strictly observational; production verdicts remain authoritative.
