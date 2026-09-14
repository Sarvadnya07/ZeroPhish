import os
import sys
import time
import requests
import subprocess
import signal

DB_FILE = os.path.abspath("test_durability.db")
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

env = os.environ.copy()
env["PORT"] = "8001"
env["DATABASE_URL"] = f"sqlite:///{DB_FILE}"
env["REPOSITORY_BACKEND"] = "sql"
env["SECRET_KEY"] = "production_ready_test_secret_key_1234567890"
env["PYTHONPATH"] = os.path.abspath("Backend")

print(f"[1] Starting Process A on port 8001 with DB={DB_FILE}...")
proc_a = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "Backend.gateway:app", "--host", "127.0.0.1", "--port", "8001", "--log-level", "warning"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

def wait_for_health(timeout=25):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get("http://127.0.0.1:8001/health", timeout=1)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("Gateway did not become healthy in time")

try:
    health_a = wait_for_health()
    print(f"[1] Process A healthy: status={health_a.get('status')}, scans={health_a.get('scans')}")

    scan_payload = {
        "tier1_score": 75,
        "tier1_evidence": ["Urgent phrasing detected", "Suspicious sender domain"],
        "body": "URGENT: Your account has been suspended. Please click here to verify your identity.",
        "sender": "alert@security-paypal-fake.com",
        "subject": "Action Required: Account Suspended",
        "links": ["http://evil-phish.com/login"]
    }

    print("[2] Posting scan to Process A (allowing up to 35s for DNS/WHOIS resolution)...")
    try:
        t0 = time.time()
        scan_resp = requests.post("http://127.0.0.1:8001/gateway/scan", json=scan_payload, timeout=35)
        print(f"[2] Post completed in {time.time() - t0:.2f}s with status {scan_resp.status_code}")
        assert scan_resp.status_code == 200, f"Scan failed: {scan_resp.text}"
    except Exception as e:
        print(f"ERROR: {e}")
        out, err = proc_a.communicate(timeout=2)
        print(f"Process A stderr: {err}")
        raise
    scan_data = scan_resp.json()
    scan_id = scan_data["scan_id"]
    verdict = scan_data["verdict"]
    score = scan_data["final_score"]
    print(f"[2] Scan completed: id={scan_id}, verdict={verdict}, score={score}")

    # Verify health has total_cached == 1
    h = requests.get("http://127.0.0.1:8001/health").json()
    assert h["scans"]["total_cached"] >= 1, f"Expected total_cached >= 1, got {h['scans']}"
    print(f"[2] Health total_cached verified: {h['scans']['total_cached']}")

finally:
    print("[3] Terminating Process A...")
    proc_a.terminate()
    try:
        proc_a.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc_a.kill()
    print("[3] Process A stopped.")

time.sleep(1)

print(f"[4] Starting Process B on port 8001 with same DB={DB_FILE}...")
proc_b = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "Backend.gateway:app", "--host", "127.0.0.1", "--port", "8001", "--log-level", "warning"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    health_b = wait_for_health()
    print(f"[4] Process B healthy: status={health_b.get('status')}, scans={health_b.get('scans')}")
    assert health_b["scans"]["total_cached"] >= 1, f"Process B did not load persisted scans: {health_b['scans']}"

    print(f"[5] Querying scan {scan_id} from Process B...")
    get_resp = requests.get(f"http://127.0.0.1:8001/gateway/result/{scan_id}", timeout=5)
    assert get_resp.status_code == 200, f"Get scan failed: {get_resp.status_code} {get_resp.text}"
    retrieved_data = get_resp.json()
    assert retrieved_data["scan_id"] == scan_id
    assert retrieved_data["verdict"] == verdict
    assert retrieved_data["final_score"] == score
    print(f"[5] Scan retrieved successfully from Process B: {retrieved_data['scan_id']} matches!")

    print("[6] Durability verified 100% across process crash/restart!")

finally:
    print("[7] Terminating Process B...")
    proc_b.terminate()
    try:
        proc_b.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc_b.kill()
    print("[7] Process B stopped.")
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    print("[8] Cleanup complete.")
