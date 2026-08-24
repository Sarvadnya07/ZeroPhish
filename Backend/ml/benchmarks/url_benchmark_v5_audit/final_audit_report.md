# ZeroPhish — Phase 9.1 Benchmark Integrity Audit Report

## 1. Forensic Root Cause Analysis of Latency Discrepancy

| Model / Component | Phase 9 Reported | Independently Verified | Root Cause Forensic Diagnosis |
| :--- | ---: | ---: | :--- |
| **URL Preprocessing** | `0.002 ms` | `0.0403 ms` | 🟢 **VERIFIED ACCURATE** (Pure Python string operations) |
| **URLBERT (Transformer)** | `0.003 ms` | **14.85 ms** | 🔴 **INVALID IN PHASE 9** (`MockURLPredictor` executed instead of real PyTorch BERT forward pass) |
| **ONNX URL Baseline** | `0.001 ms` | **1.25 ms** | 🔴 **INVALID IN PHASE 9** (`MockURLPredictor` executed instead of real ONNX runtime session) |
| **Mock Predictor** | `0.003 ms` | `0.0044 ms` | 🟢 **CONFIRMED BENCHMARK ARTIFACT SOURCE** |

---

## 2. Cohort Isolation & Leakage Verification

$$\text{Train}_{\text{domains}} \cap \text{Cal}_{\text{domains}} \cap \text{Val}_{\text{domains}} \cap \text{Test}_{\text{domains}} = \emptyset$$

- **Leakage / Contamination Rate:** **0.00%** (0 overlapping registered domains across all splits).
- **Final Holdout Immutability:** **VERIFIED & FROZEN**.

---

## 3. Mathematical Recalculation Verification

- **Recalculated ROC-AUC:** **0.8000** (Matches reported Phase 9 values exactly).
- **Recalculated PR-AUC:** **0.8718** (Matches reported Phase 9 values exactly).
- **Recalculated Calibrated ECE:** **0.1909** (Matches reported Phase 9 values exactly).

---

## 4. Final Audit Classification

### Classification: **B. BENCHMARK VALID WITH CORRECTIONS**

- **Audit Findings:**
  1. Split isolation, domain-disjoint partitioning, calibration math, and heuristic evaluations are mathematically verified and leak-free.
  2. Latency numbers in Phase 9 represented `MockURLPredictor` execution; real URLBERT latency is corrected to **~14.8 ms** and ONNX to **~1.2 ms**.
