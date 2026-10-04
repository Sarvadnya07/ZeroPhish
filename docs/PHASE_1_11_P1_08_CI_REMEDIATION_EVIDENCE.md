# P1-08 CI Durability Test Contract Remediation Evidence

## Original Failure
In GitHub Actions CI (Workflow: `ZeroPhish CI`, Job: `Backend Tests, Migrations & Coverage`, Step: `Run multi-process restart durability verification`):
```text
test_blackbox_process_restart_durability
assert retrieved["final_score"] == score
E assert 82.2 == None
```

## Root Cause
When submitting an asynchronous scan via `POST /gateway/scan`, the initial response returns intermediate partial state (`complete=False`, `final_score=None`) while background tiers (Tier 3 AI analysis and fusion) execute asynchronously.

The black-box durability test previously captured `score = scan_data["final_score"]` immediately from the initial `POST /gateway/scan` response (where `final_score` was legitimately `None`).
Subsequently, Process A was terminated, and Process B was spawned against the same SQLite database. Process B correctly loaded the persisted record which had completed in the background, containing the authoritative score (`final_score=82.2`).
The assertion `assert retrieved["final_score"] == score` failed because the test was asserting against the transient initial response value (`None`) instead of the authoritative completed scan result.

## Exact Test-Contract Correction
1. **Authoritative Polling Helper**: Added `_wait_for_scan_completion(port, scan_id, timeout=25.0)` to poll `/gateway/result/{scan_id}` until `complete is True` and `final_score is not None`.
2. **Authoritative Pre-Termination Validation in Process A**:
   - If the initial submission response has not completed, poll until authoritative completion.
   - Capture `verdict` and `score` from the completed authoritative result.
   - Assert `score is not None` and `verdict is not None` before Process A is terminated.
3. **Post-Restart Cross-Process Verification in Process B**:
   - Query `/gateway/result/{scan_id}` from Process B.
   - Assert `retrieved["complete"] is True`.
   - Assert `retrieved["verdict"] == verdict`.
   - Assert `retrieved["final_score"] == score` (matching the authoritative completed value captured from Process A).

## Production vs Test Invariance
- Zero production code was modified (`Backend/` source code is 100% untouched).
- Gateway scoring, detection heuristics, and repository persistence mechanisms were preserved intact.
- Process-boundary properties remain strictly preserved: Process A and Process B run as completely separate OS subprocesses (`uvicorn` instances via `subprocess.Popen`) sharing only the disk-backed SQLite database file.

## Verification & Test Results
- **Targeted Test**: `test_blackbox_durability.py`: **1 passed in 25.08s**
- **Lifecycle & Durability Suite**: `Backend/tests/test_p1_01a_lifecycle.py`, `Backend/tests/test_completion_gaps.py`, `Backend/tests/test_p1_reliability.py`, `Backend/tests/test_repositories.py`, `test_blackbox_durability.py`: **38 passed in 47.68s**
- **Complete CI Suite**: `Backend/tests/`: **639 passed in 168.93s** (Total coverage: **80%**, easily exceeding the `--fail-under=65` gate).
