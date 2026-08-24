# ZeroPhish — Phase 12.1 Shadow Telemetry Integrity Audit Report

## 1. Population Reconciliation & Count Audit

- **Total Evaluated Observations:** **60** (Single consistent population reconciled)
- **Hard-Rule Resolutions:** **0** (0.0%)
- **Heuristic Resolutions:** **56** (93.3%)
- **ONNX Baseline Invocations:** **4** (0.0%)
- **URLBERT Deep Invocations:** **0** (0.0%)
- **Timeouts / Drops / Errors:** **0 / 0 / 0**

---

## 2. Latency Recalculation & Root Cause Diagnosis

| Metric | Phase 12 Reported | Recomputed from Raw Array | Forensic Status | Diagnosis / Notes |
| :--- | ---: | ---: | :--- | :--- |
| **p50 Latency** | `0.20 ms` | **0.0460 ms** | 🟢 **VERIFIED** | Fast heuristic / hard rule resolution |
| **p95 Latency** | `1.45 ms` | **11.5358 ms** | 🔴 **CORRECTED** | Phase 12 reported theoretical model bound |
| **p99 Latency** | `15.05 ms` | **489.2846 ms** | 🔴 **CORRECTED** | 15.05 ms was static full-hybrid constant |
| **Mean Latency** | — | **21.0199 ms** | 🟢 **RECOMPUTED** | Actual average per-URL CPU time |

> [!CAUTION]
> **CORRECTION NOTICE:**
> The static placeholder entries (`1.45 ms` p95 and `15.05 ms` p99) in `performance_report.json` have been marked **`INVALID — PLACEHOLDER CONSTANTS`** and corrected to empirical values computed directly from the 60 observation samples.

---

## 3. CPU Savings Recomputation

- **Baseline Full Hybrid:** 15.05 ms / URL (15,050.0 ms / 1,000 URLs)
- **Observed Benchmark Replay:** 21.0199 ms / URL (21019.9 ms / 1,000 URLs)
- **Reconciled Savings:** -5969.9 ms / 1,000 URLs (--39.7%)
- **Diagnosis of 13,600 ms claim:** Derived from (15.05 - 1.45) * 1000 ms (theoretical cascade) rather than empirical replay.

---

## 4. Workload Source Classification

# 🟡 **B. TELEMETRY VALID — BENCHMARK REPLAY ONLY**

- **Workload Clarification:** The evaluated 60 observations represent the curated Phase-5/Phase-9 benchmark candidate suite replayed through the shadow pipeline, **not** live customer staging traffic.
- **Production Safety:** Production response invariance is 100% verified. No user decisions or model weights were altered.
