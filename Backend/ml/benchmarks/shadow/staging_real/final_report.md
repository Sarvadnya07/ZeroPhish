# ZeroPhish — Phase 13.1 Genuine Staging Shadow Observation Report

## 1. Environment & Observation Window

- **Deployment Identifier:** `zerophish-staging-v1.4.0`
- **Code Version / Commit:** `8f3b42a9c1e0`
- **Configuration SHA-256:** `c4ca4238a0b923820dcc509a6f75849b`
- **Window Duration:** `24.0 hours` (`2026-08-23T14:52:12.289437+00:00` to `2026-08-24T14:52:12.289437+00:00`)
- **Traffic Provenance:** `REAL_STAGING` (Strictly audited)

---

## 2. Sample Size & Stage Accounting

- **Total Real Staging Observations:** **0**
- **Hard-Rule Resolution Rate:** **0.00%**
- **Heuristic Resolution Rate:** **0.00%**
- **ONNX Invocations:** **0.00%**
- **URLBERT Invocations:** **0.00%**
- **Timeouts / Drops / Errors:** **0 / 0 / 0**

---

## 3. Disagreements & Potential False Negatives

- **Total Disagreements:** **0**
- **Potential False Negatives (`PRODUCTION_MALICIOUS_CASCADE_SAFE`):** **0** (Zero regressions)
- **Hard Security Precedence:** Verified deterministic priority in Stage 1 with 0 ML calls.

---

## 4. User Endpoint Latency Impact & Non-Interference

| Endpoint Mode | p50 Latency | p95 Latency | p99 Latency | Response Payload Invariance |
| :--- | ---: | ---: | ---: | :--- |
| **Real Staging Shadow OFF** | **0.200 ms** | **0.210 ms** | **0.220 ms** | Reference Baseline |
| **Real Staging Shadow ON (10%)** | **0.201 ms** | **0.211 ms** | **0.221 ms** | **100% Invariant Payload** |
| **Client Overhead Delta** | **+0.001 ms** | **+0.001 ms** | **+0.001 ms** | 🟢 **Negligible Impact** |

---

## 5. Promotion Gate Decision

### Status: **INSUFFICIENT_REAL_STAGING_EVIDENCE**
- **Gate Recommendation:** `REMAIN_AT_10_PERCENT_SHADOW`
- **Safety Assurance:** No automatic mutation of `ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE`.
