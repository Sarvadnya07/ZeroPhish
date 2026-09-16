"""
Phase 1 Acceptance: Multi-Process Circuit Breaker Test Harness.
Executes two independent OS processes and reports empirical observations.
"""
import os
import subprocess
import sys
import time

PYTHON_EXE = sys.executable
WORKER_SCRIPT = os.path.join(os.path.dirname(__file__), "process_worker.py")

def run_worker(mode: str, breaker_name: str, env_override=None):
    env = os.environ.copy()
    if env_override:
        env.update(env_override)
    proc = subprocess.Popen(
        [PYTHON_EXE, WORKER_SCRIPT, mode, breaker_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    out, err = proc.communicate(timeout=10)
    return proc.pid, proc.returncode, out.strip(), err.strip()

def test_multiprocess():
    print("==================================================")
    print("PHASE 1: MULTI-PROCESS CIRCUIT BREAKER TEST")
    print("==================================================")

    # 1. Test Default Process-Local Isolation Mode (No Redis)
    print("\n[Scenario 1] Default Process-Local Isolation (2 independent OS processes):")
    breaker_name = f"proc_local_{int(time.time())}"
    
    env_no_redis = {"REDIS_URL": ""}
    pid_a, code_a, out_a, err_a = run_worker("trip", breaker_name, env_no_redis)
    print(f"  Worker A (PID={pid_a}, exit={code_a}): {out_a}")

    pid_b, code_b, out_b, err_b = run_worker("status", breaker_name, env_no_redis)
    print(f"  Worker B (PID={pid_b}, exit={code_b}): {out_b}")

    assert "STATE=open" in out_a or "IS_OPEN=True" in out_a
    assert "STATE=closed" in out_b or "CALL_RESULT=ok" in out_b
    print("  -> EMPIRICAL PROOF: In default process-local mode, Worker A trip does not affect Worker B.")
    print("  -> Result: PASS (Process-local isolation across OS processes verified).")

    # 2. Test Redis-Coordinated Distributed Mode
    print("\n[Scenario 2] Redis-Coordinated Distributed Mode (Real Redis):")
    # Check if a real Redis server is reachable on port 6379
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    redis_available = False
    try:
        s.connect(("127.0.0.1", 6379))
        s.close()
        redis_available = True
    except Exception:
        pass

    if not redis_available:
        print("  -> Redis Probe: No real Redis daemon reachable on 127.0.0.1:6379 (host environment lacks native Redis / Docker stopped).")
        print("  -> Architectural Classification: Single-instance supported architecture is PROVEN.")
        print("  -> Distributed Multi-Process Redis Synchronization: NOT PROVEN on this host due to absent Redis daemon.")
        return "PARTIAL", "Process-local isolation PROVEN; Real Redis daemon unavailable on Windows host"
    else:
        print("  -> Redis Probe: Real Redis daemon detected at 127.0.0.1:6379.")
        dist_name = f"dist_{int(time.time())}"
        pid_c, code_c, out_c, _ = run_worker("trip", dist_name, {"REDIS_URL": "redis://127.0.0.1:6379"})
        pid_d, code_d, out_d, _ = run_worker("status", dist_name, {"REDIS_URL": "redis://127.0.0.1:6379"})
        print(f"  Worker C (PID={pid_c}): {out_c}")
        print(f"  Worker D (PID={pid_d}): {out_d}")
        if "REJECTED=TRUE" in out_d or "STATE=open" in out_d:
            print("  -> Result: PASS (Real Redis multi-process coordination verified).")
            return "PASS", "Both process-local isolation and Redis distributed mode verified."
        else:
            return "FAIL", f"Worker D did not observe OPEN state: {out_d}"

if __name__ == "__main__":
    status, notes = test_multiprocess()
    print(f"\nPhase 1 Outcome: {status} ({notes})")
