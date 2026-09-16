"""
Process Worker for Multi-Process Circuit Breaker Acceptance.
Can run as an independent OS process, report PID, manipulate circuit state,
and report observed state via stdout / command argument.
"""
import asyncio
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent / "Backend"
sys.path.insert(0, str(BACKEND_DIR))

from circuit_breaker import CircuitBreaker, CircuitBreakerOpenError, CircuitState

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "status"
    name = sys.argv[2] if len(sys.argv) > 2 else "p1_test_breaker"
    redis_url = os.getenv("REDIS_URL", "")

    breaker = CircuitBreaker(
        failure_threshold=2,
        timeout=5.0,
        window=30.0,
        name=name,
    )
    pid = os.getpid()

    if mode == "trip":
        # Trip breaker by recording 2 failures
        async def fail():
            raise ValueError("simulated failure")
        for _ in range(2):
            try:
                await breaker.call(fail)
            except Exception:
                pass
        print(f"PID={pid}|ACTION=TRIP|STATE={breaker.state.value}|IS_OPEN={breaker.is_open}")

    elif mode == "status":
        # Report status
        async def probe():
            return "ok"
        try:
            res = await breaker.call(probe)
            print(f"PID={pid}|ACTION=STATUS|STATE={breaker.state.value}|CALL_RESULT={res}")
        except CircuitBreakerOpenError:
            print(f"PID={pid}|ACTION=STATUS|STATE={breaker.state.value}|REJECTED=TRUE")
        except Exception as e:
            print(f"PID={pid}|ACTION=STATUS|STATE={breaker.state.value}|ERROR={e}")

if __name__ == "__main__":
    asyncio.run(main())
