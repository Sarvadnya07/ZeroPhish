"""
Phase 3 Acceptance: Real External HTTP TCP Performance Benchmark.
Executes real network TCP requests against http://127.0.0.1:8001 (NO ASGITransport).
Individually records per-request latencies, percentiles, throughput, and error counts.
"""
import asyncio
import statistics
import time
import httpx

BASE_URL = "http://127.0.0.1:8001"

async def measure_single_request(client: httpx.AsyncClient, method: str, path: str, json_data=None):
    t0 = time.perf_counter()
    status_code = 0
    err = None
    try:
        if method == "GET":
            r = await client.get(path)
        else:
            r = await client.post(path, json=json_data)
        status_code = r.status_code
    except Exception as e:
        err = str(e)
    duration_ms = (time.perf_counter() - t0) * 1000.0
    return duration_ms, status_code, err

async def run_concurrent_batch(concurrency: int, path: str, method="GET", json_data=None):
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0, limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency)) as client:
        t_start = time.perf_counter()
        tasks = [
            measure_single_request(client, method, path, json_data)
            for _ in range(concurrency)
        ]
        results = await asyncio.gather(*tasks)
        total_time_sec = time.perf_counter() - t_start

    latencies = [r[0] for r in results]
    status_codes = [r[1] for r in results]
    errors = [r[2] for r in results if r[2] is not None or r[1] != 200]

    latencies_sorted = sorted(latencies)
    p50 = statistics.median(latencies_sorted)
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[min(int(len(latencies_sorted) * 0.99), len(latencies_sorted) - 1)]
    mean = statistics.mean(latencies_sorted)
    rps = concurrency / total_time_sec

    return {
        "concurrency": concurrency,
        "endpoint": path,
        "total_time_sec": total_time_sec,
        "rps": rps,
        "mean_ms": mean,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "min_ms": latencies_sorted[0],
        "max_ms": latencies_sorted[-1],
        "error_count": len(errors),
    }

async def benchmark_gateway_tcp():
    print("==================================================")
    print("PHASE 3: REAL EXTERNAL HTTP TCP PERFORMANCE")
    print("==================================================")
    print(f"Target: {BASE_URL} over TCP loopback (Windows Python 3.13)")

    # 1. Warm-up
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=5.0) as client:
        r = await client.get("/health")
        assert r.status_code == 200

    # 2. Run 30 concurrent /health requests
    res_30_health = await run_concurrent_batch(30, "/health")
    print(f"\n[Run 1] 30 Concurrent Requests to /health:")
    print(f"  Total Duration : {res_30_health['total_time_sec']:.3f} s")
    print(f"  Throughput     : {res_30_health['rps']:.1f} req/sec")
    print(f"  Latency (mean) : {res_30_health['mean_ms']:.2f} ms")
    print(f"  Latency (p50)  : {res_30_health['p50_ms']:.2f} ms")
    print(f"  Latency (p95)  : {res_30_health['p95_ms']:.2f} ms")
    print(f"  Latency (p99)  : {res_30_health['p99_ms']:.2f} ms")
    print(f"  Error Count    : {res_30_health['error_count']}")

    # 3. Run 100 concurrent /health requests
    res_100_health = await run_concurrent_batch(100, "/health")
    print(f"\n[Run 2] 100 Concurrent Requests to /health:")
    print(f"  Total Duration : {res_100_health['total_time_sec']:.3f} s")
    print(f"  Throughput     : {res_100_health['rps']:.1f} req/sec")
    print(f"  Latency (mean) : {res_100_health['mean_ms']:.2f} ms")
    print(f"  Latency (p50)  : {res_100_health['p50_ms']:.2f} ms")
    print(f"  Latency (p95)  : {res_100_health['p95_ms']:.2f} ms")
    print(f"  Latency (p99)  : {res_100_health['p99_ms']:.2f} ms")
    print(f"  Error Count    : {res_100_health['error_count']}")

    # 4. Run 30 concurrent lightweight scan cache hits
    scan_payload = {
        "body": "Static benchmark content for cache hit testing.",
        "sender": "bench@company.com",
        "subject": "Benchmark",
        "tier1_score": 10,
        "tier1_evidence": ["benchmark"],
        "links": []
    }
    # Pre-populate cache
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        await client.post("/api/v1/scan", json=scan_payload)

    res_30_scan = await run_concurrent_batch(30, "/api/v1/scan", method="POST", json_data=scan_payload)
    print(f"\n[Run 3] 30 Concurrent Requests to /api/v1/scan (Production Pipeline / Cache Hit):")
    print(f"  Total Duration : {res_30_scan['total_time_sec']:.3f} s")
    print(f"  Throughput     : {res_30_scan['rps']:.1f} req/sec")
    print(f"  Latency (mean) : {res_30_scan['mean_ms']:.2f} ms")
    print(f"  Latency (p50)  : {res_30_scan['p50_ms']:.2f} ms")
    print(f"  Latency (p95)  : {res_30_scan['p95_ms']:.2f} ms")
    print(f"  Latency (p99)  : {res_30_scan['p99_ms']:.2f} ms")
    print(f"  Error Count    : {res_30_scan['error_count']}")

    assert res_30_health['error_count'] == 0
    assert res_100_health['error_count'] == 0
    assert res_30_scan['error_count'] == 0
    print("\nPhase 3 Outcome: PASS (Real TCP network performance benchmark complete with 0 errors)")
    return True

if __name__ == "__main__":
    asyncio.run(benchmark_gateway_tcp())
