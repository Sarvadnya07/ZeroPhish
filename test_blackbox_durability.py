"""
ZeroPhish - Black-box Multi-Process Durability and Restart Test.

Lifecycle Boundary Tested:
- Validates process crash/restart lifecycle boundary under SQL persistence.
- Process A starts with standalone SQLite database and records a scan.
- Process A is terminated (crash simulation).
- Process B starts against the exact same SQLite database.
- Process B loads existing scan state on startup and serves the persisted scan_id.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from typing import Any

import pytest
import requests


def _find_free_port() -> int:
    """Find an available TCP port on localhost to avoid port collision."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_health(port: int, timeout: float = 25.0) -> dict[str, Any]:
    """Poll the /health endpoint until HTTP 200 or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError(f"Gateway on port {port} did not become healthy within {timeout}s")


def _wait_for_scan_completion(port: int, scan_id: str, timeout: float = 25.0) -> dict[str, Any]:
    """
    Poll the authoritative /gateway/result/{scan_id} endpoint until complete or timeout.
    Returns the authoritative completed scan result dictionary.
    """
    start = time.time()
    last_status = None
    while time.time() - start < timeout:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/gateway/result/{scan_id}", timeout=2.0)
            if r.status_code == 200:
                data = r.json()
                if data.get("complete") is True and data.get("final_score") is not None:
                    return data
                last_status = f"HTTP 200 but complete={data.get('complete')}, final_score={data.get('final_score')}"
            else:
                last_status = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as exc:
            last_status = f"Exception: {exc}"
        time.sleep(0.5)
    raise TimeoutError(
        f"Scan {scan_id} on port {port} did not complete within {timeout}s. Last status: {last_status}"
    )


def _terminate_process(proc: subprocess.Popen) -> None:
    """Reliably terminate a subprocess across POSIX and Windows."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    # Ensure stdout/stderr pipes are closed to prevent handle inheritance leaks
    for pipe in (proc.stdout, proc.stderr, proc.stdin):
        if pipe and not pipe.closed:
            try:
                pipe.close()
            except Exception:
                pass
    time.sleep(0.5)


@pytest.mark.durability
def test_blackbox_process_restart_durability(tmp_path):
    """
    Verify durable persistence across an actual multi-process crash/restart boundary.

    Test Lifecycle Steps:
    1. Initialize a dedicated SQLite database in tmp_path.
    2. Spawn Process A (uvicorn Gateway) bound to the database.
    3. Execute a scan through Process A and verify scan caching.
    4. Terminate Process A (simulating process failure / shutdown).
    5. Spawn Process B (new uvicorn Gateway process) bound to the identical database file.
    6. Verify Process B successfully reloads previous scans on startup and serves the scan result.
    """
    db_file = tmp_path / "test_durability.db"
    db_path = str(db_file.resolve())
    port = _find_free_port()

    repo_root = os.path.abspath(os.path.dirname(__file__))
    backend_dir = os.path.join(repo_root, "Backend")

    env = os.environ.copy()
    env["PORT"] = str(port)
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    env["REPOSITORY_BACKEND"] = "sql"
    env["SECRET_KEY"] = "production_ready_test_secret_key_1234567890"
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{backend_dir}{os.pathsep}{repo_root}" + (f"{os.pathsep}{existing_pp}" if existing_pp else "")

    # -------------------------------------------------------------
    # Step 1: Start Process A
    # -------------------------------------------------------------
    proc_a = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "gateway:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=backend_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    scan_id = None
    verdict = None
    score = None

    try:
        health_a = _wait_for_health(port=port, timeout=30.0)
        assert health_a.get("status") == "healthy"

        scan_payload = {
            "tier1_score": 75,
            "tier1_evidence": ["Urgent phrasing detected", "Suspicious sender domain"],
            "body": "URGENT: Your account has been suspended. Please click here to verify your identity.",
            "sender": "alert@security-paypal-fake.com",
            "subject": "Action Required: Account Suspended",
            "links": ["http://evil-phish.com/login"],
        }

        scan_resp = requests.post(
            f"http://127.0.0.1:{port}/gateway/scan", json=scan_payload, timeout=35.0
        )
        assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"

        scan_data = scan_resp.json()
        scan_id = scan_data["scan_id"]

        # If scan is incomplete, poll authoritative endpoint until completion
        if not scan_data.get("complete") or scan_data.get("final_score") is None:
            completed_result = _wait_for_scan_completion(port=port, scan_id=scan_id, timeout=25.0)
            verdict = completed_result["verdict"]
            score = completed_result["final_score"]
        else:
            verdict = scan_data["verdict"]
            score = scan_data["final_score"]

        assert score is not None, f"Authoritative scan {scan_id} final_score is None after completion"
        assert verdict is not None, f"Authoritative scan {scan_id} verdict is None after completion"

        # Verify scan record registered in health metric
        health_check_a = requests.get(f"http://127.0.0.1:{port}/health", timeout=5.0).json()
        assert health_check_a["scans"]["total_cached"] >= 1

    finally:
        _terminate_process(proc_a)

    assert scan_id is not None, "Scan ID was not generated by Process A"

    # Give OS socket / file handle a brief moment to settle
    time.sleep(1.0)

    # -------------------------------------------------------------
    # Step 2: Start Process B with the same database
    # -------------------------------------------------------------
    proc_b = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "gateway:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=backend_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        health_b = _wait_for_health(port=port, timeout=30.0)
        assert health_b.get("status") == "healthy"
        assert (
            health_b["scans"]["total_cached"] >= 1
        ), f"Process B did not reload persisted scans: {health_b['scans']}"

        # Step 3: Query the scan from Process B
        get_resp = requests.get(f"http://127.0.0.1:{port}/gateway/result/{scan_id}", timeout=5.0)
        assert get_resp.status_code == 200, f"Get scan failed: {get_resp.status_code} {get_resp.text}"

        retrieved = get_resp.json()
        assert retrieved["scan_id"] == scan_id
        assert retrieved["complete"] is True, f"Expected persisted scan to be complete, got: {retrieved.get('complete')}"
        assert retrieved["verdict"] == verdict
        assert retrieved["final_score"] == score

    finally:
        _terminate_process(proc_b)


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        print("[Standalone Invocation] Running durability test in temporary directory:", td)
        test_blackbox_process_restart_durability(Path(td))
        print("[Standalone Invocation] Black-box durability test PASSED!")
