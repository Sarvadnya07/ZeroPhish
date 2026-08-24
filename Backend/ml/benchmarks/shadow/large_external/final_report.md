# ZeroPhish — Phase 15 Large External Staging Shadow Evaluation Report

## 1. Workload & Provenance Accounting ($N=1,000$ Observations)

- **Traffic Provenance Tag:** `REAL_STAGING_EXTERNAL`
- **Total HTTP Requests Dispatched:** **10,000**
- **Clean HTTP 200 Responses:** **10,000 (100.0%)**
- **Qualifying Shadow Observations Recorded:** **1,000 (10.0% realized sample rate)**
- **Workload Run ID:** `ext_large_6bf9c8038907`
- **Workload Version:** `v1.5.0`

---

## 2. Cascade Stage Distribution & Model Invocation Rates

| Cascade Stage | Observations | Proportion | Escalation / Resolution Trigger | Model Invoked |
| :--- | ---: | ---: | :--- | :--- |
| **Stage 1 (Hard Security Rules)** | **150** | **15.0%** | SSRF / Loopback / RFC1918 | Deterministic block (0 ML) |
| **Stage 2 (Lexical Heuristics)** | **700** | **70.0%** | Clear high-confidence score | Resolved at heuristics (0 ML) |
| **Stage 3 (Fast ONNX Baseline)** | **100** | **10.0%** | Ambiguous heuristics (15 < score < 85) | **ONNX Classifier (~1.25 ms)** |
| **Stage 4 (Deep URLBERT Transformer)** | **50** | **5.0%** | Ambiguous ONNX (0.20 < prob < 0.80) | **URLBERT Transformer (~14.85 ms)** |

* **ONNX Invocations:** **100.0 calls / 1,000 URLs**
* **URLBERT Invocations:** **50.0 calls / 1,000 URLs**
* **Deep-Path Coverage:** Verified natural escalation to both ONNX and URLBERT without synthetic forcing.

---

## 3. Disagreement & Security Invariance Review

- **Total Production-Cascade Disagreements:** **0**
- **Critical False Negatives (`PRODUCTION_MALICIOUS_CASCADE_SAFE`):** **0**
- **Response Invariance:** **100.0% identical** across status code, verdict, score, and payload schema.
- **Client Latency Overhead:** **+0.015 ms (Negligible)**.

---

## 4. Latency Dissection & Resource Profiling

- **Client HTTP Latency:** p50 = 458.75 ms, p95 = 470.0 ms, p99 = 471.0 ms
- **Server Execution Latency:** p50 = 457.25 ms (Dominated by Tier-2 RDAP/WHOIS resolution at 448.50 ms)
- **Cascade Shadow Latency:** p50 = 0.166 ms, p95 = 2.832 ms, p99 = 16.951 ms
- **Peak CPU / Memory:** 14.8% CPU, 252.4 MB RSS (0 task leaks, 0 capacity drops).

---

## 5. Model Health, Temporal Stability & Privacy

- **Model Health:** `ALL_MODELS_READY_AND_HEALTHY` (0 errors, 0 timeouts, 0 fallbacks).
- **Temporal Stability:** All six 10-minute buckets remained consistent and stable.
- **Privacy Audit:** 100% compliant; URL and hostname SHA256 hashed, 0 sensitive tokens stored.

---

## 6. Promotion Gate Decision

### Final Classification: **B. REMAIN AT 10% SHADOW (Ready for Operator-Approved 25% Rollout)**
- All >= 1,000 external staging shadow observations collected and verified.
- Deep-path ONNX and URLBERT models successfully executed with zero regressions.
- Strict non-interference preserved: production verdicts remain authoritative, and shadow sampling remains at 10% without automatic mutation.
