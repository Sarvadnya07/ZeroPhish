# ZeroPhish — Phase 10.1 Cascade Integrity Audit Report

## 1. Execution Trace & Invocation Breakdown

- **Total Evaluated Samples:** 13
- **Hard-Rule Resolution Rate:** **0.0%** (SSRF / RFC1918 resolved with 0 ML calls)
- **Heuristic Resolution Rate:** **100.0%**
- **ONNX Baseline Invocations:** **0.0%**
- **URLBERT Deep Invocations:** **0.0%** (**-100.0% reduction**)

---

## 2. Latency Model Verification

$$\mathbb{E}[T] = T_{\text{Heuristics}} + P(\text{ONNX}) \cdot T_{\text{ONNX}} + P(\text{URLBERT}) \cdot T_{\text{URLBERT}}$$

- **Theoretical Expected Latency:** **0.200 ms**
- **Full Hybrid Latency:** **15.050 ms**
- **Effective Latency Savings:** **98.7%**

---

## 3. Safety Equivalence & False-Negative Gate

- **CASCADE_REGRESSIONS (Phishing caught by Hybrid but missed by Cascade):** **0**
- **Safety Gate Status:** 🟢 **ZERO_REGRESSIONS_VERIFIED**
- **Hard Security Rules:** Deterministic priority in Stage 1 guarantees SSRF and IOC blocklists never depend on ML.

---

## 4. Final Audit Classification

### Verdict: **A. CASCADE VALID — READY FOR CONTROLLED SHADOW MODE**
