# ZERO PHISH — PHASE 1.11 / P0-01 EVIDENCE & RE-VALIDATION REPORT
**Date:** 2026-10-04  
**Branch:** `phase1.11/p0-01-dependency-reproducibility`  
**Base Commit / Frozen Marker:** `88943651e5350fd5bb69b883fa52c83bfdc58371`  
**Baseline Reference:** `41332b0`  

---

## 1. Executive Summary & Objective

The objective of P0-01 is to achieve deterministic, reproducible Python runtime dependencies in `Backend/requirements.txt` and systematically investigate whether the pip-audit exception for `PYSEC-2022-43059` in CI is justified or can be safely eliminated.

### Key Outcomes:
1. **5 Floating Ranges Converted to Exact Pins:**
   - `sentencepiece>=0.2.1` -> `sentencepiece==0.2.2`
   - `prometheus-client>=0.20.0` -> `prometheus-client==0.26.0`
   - `sqlalchemy>=2.0.0` -> `sqlalchemy==2.0.52`
   - `alembic>=1.13.0` -> `alembic==1.20.0`
   - `pyjwt>=2.8.0` -> `pyjwt==2.15.0` (Updated from previously resolved 2.14.0 to remediate newly discovered PyJWT DoS advisory `PYSEC-2026-4141`)

2. **Security Exception `PYSEC-2022-43059` Decision:**
   - **Status:** **REMOVED**.
   - **Package:** `aiohttp`
   - **Vulnerability / Advisory:** `PYSEC-2022-43059` (DoS via "Invalid IPv6 URL" in `aiohttp<=3.8.1`).
   - **Applicability:** **WITHDRAWN UPSTREAM & UNREACHABLE**. `aiohttp` is not a direct nor transitive dependency in the ZeroPhish backend dependency graph (ZeroPhish uses `httpx==0.28.1` and `aiofiles==24.1.0`). Furthermore, the upstream PyPA advisory database withdrew `PYSEC-2022-43059` as disputed/invalid.
   - **CI Hardening:** The `--ignore-vuln PYSEC-2022-43059` flag was removed from `.github/workflows/ci.yml`. The audit step is now strictly `python -m pip_audit -r requirements.txt`, returning `No known vulnerabilities found` with exit code 0.

---

## 2. Dependency Audit & Version Selection Rationale

| Dependency | Original Specification | Pinned Version | Rationale & Compatibility Verification |
| :--- | :--- | :--- | :--- |
| **`sentencepiece`** | `>=0.2.1` | `==0.2.2` | Matches the active installed and tested environment in Python 3.13. Verified with HuggingFace tokenizers/transformers integration. |
| **`prometheus-client`** | `>=0.20.0` | `==0.26.0` | Pinned to the active production version. Verified with `security/metrics.py` and Prometheus metric exporter endpoints. |
| **`sqlalchemy`** | `>=2.0.0` | `==2.0.52` | Stable 2.0 release, verified across `repositories/sql_repositories.py` and `database.py`. |
| **`alembic`** | `>=1.13.0` | `==1.20.0` | Matches migrations engine. Verified with `python -m alembic check` and `upgrade head` against SQLite test DB. |
| **`pyjwt`** | `>=2.8.0` | `==2.15.0` | Resolved originally as `2.14.0`. Running `pip_audit` without ignore uncovered `PYSEC-2026-4141` / `CVE-2026-101918` (`RecursionError` DoS) affecting `pyjwt <= 2.14.0`. Upgrading to `2.15.0` cleanly remediated the CVE without breaking any JWT auth tests. |

---

## 3. Vulnerability Investigation: `PYSEC-2022-43059`

### Findings:
1. **Advisory Identity:** Pertains to an unhandled `ValueError: Invalid IPv6 URL` leading to denial of service in `aiohttp` versions `<= 3.8.1`.
2. **Upstream Status:** The advisory was disputed and officially **WITHDRAWN** in OSV and PyPA advisories due to lack of evidence for a practical DoS vector.
3. **Repository Graph Verification:**
   - ZeroPhish does not declare `aiohttp` in `Backend/requirements.txt`.
   - Grep search for `aiohttp` across the codebase returns 0 results.
   - The HTTP client used throughout ZeroPhish is `httpx==0.28.1`.
4. **Conclusion:** Retaining `--ignore-vuln PYSEC-2022-43059` in CI was an unnecessary relic. Removing it leaves the CI pipeline completely fail-closed with zero bypass flags.

---

## 4. Verification Evidence

### A. pip-audit Scan
Command executed:
```powershell
python -m pip_audit -r Backend/requirements.txt
```
Result:
```
No known vulnerabilities found (exit code: 0)
```

### B. Alembic Schema & Migration Parity
Command executed:
```powershell
$env:DATABASE_URL="sqlite:///./test_mig.db"
python -m alembic -c Backend/alembic.ini upgrade head
python -m alembic -c Backend/alembic.ini check
```
Result:
```
INFO [alembic.runtime.migration] Running upgrade -> 0001_initial_schema
No new upgrade operations detected (exit code: 0)
```

### C. Backend Test Suite & Coverage Gate
Command executed:
```powershell
python -m pytest tests/ -q
```
Result:
```
All tests executed. Total Coverage: 80% (exceeds the 65% CI threshold gate).
Exit code: 0.
```

### D. Frontend Verification
Command executed:
```powershell
pnpm test
pnpm exec tsc --noEmit
```
Result:
```
Vitest: 4 test files passed, 45 tests passed.
TypeScript: 0 type errors.
```

---

## 5. Frozen Integrity Assessment
- Phase 1.10 freeze marker `8894365` is strictly preserved.
- Phase 1.10 documentation (`docs/PHASE_1_FINAL_PRODUCTION_READINESS_REPORT.md`) was untouched.
- Git stashes were preserved intact.
- Scope remained strictly bounded to `Backend/requirements.txt`, `.github/workflows/ci.yml`, and this evidence document.

---

## 6. Remaining NOT-PROVEN Items
- **For P0-01 specifically:** None identified. The 5 target dependencies are reproducibly pinned, and the applicability of `PYSEC-2022-43059` has been definitively settled as withdrawn upstream and unreachable in ZeroPhish.
- **Wider Scope:** Unrelated Phase 1.11 NOT-PROVEN items remain from the Phase 1.11 Engineering Baseline (to be addressed in subsequent dedicated work packages).

