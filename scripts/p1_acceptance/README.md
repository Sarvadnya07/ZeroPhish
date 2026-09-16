# P1 Acceptance Scripts (manual, not part of pytest)

These are **manual benchmark / fault-injection harnesses**, not automated tests.

- They are named `test_*` only to match their original acceptance-phase naming; **pytest does not collect them** (they live outside `Backend/tests/` and require a live server).
- They require a running gateway (default `http://127.0.0.1:8001` — see `BASE_URL` in each script) and, for the webhook/SSE probes, reachable local receiver endpoints.
- Results from runs executed during the P1 phase are recorded in `docs/ZERO_PHISH_P1_RELIABILITY_REPORT.md` (pinned to the P1 baseline commit).

## Contents

| Script | What it exercises |
|---|---|
| `test_http_tcp_performance.py` | Real-TCP latency benchmark: cold scan, cache hit, 10-way concurrent burst; p50/p95/p99 |
| `test_circuit_multiprocess.py` | Circuit-breaker fast-fail under a separate-process upstream failure |
| `test_sse_network.py` | SSE stream backpressure: slow consumer + abrupt disconnect |
| `test_webhook_network.py` | Webhook dispatch against a local receiver: delivery, failure isolation |
| `process_worker.py` | Helper async worker used by the multiprocess circuit probe |

## Running

Start the gateway first, then run a script explicitly, e.g.:

```bash
cd Backend
../.venv/Scripts/python ../scripts/p1_acceptance/test_http_tcp_performance.py
```

Do not add these to CI as blocking gates: they depend on real network/TCP behavior and are intentionally kept out of the deterministic pytest suite.
