#!/usr/bin/env python3
"""
Vision API Benchmark Script

Measures performance of the /vision/analyze endpoint with configurable
concurrency, request count, and payload. Supports in-process (ASGITransport)
and real HTTP endpoints.

Usage:
    python benchmark_vision.py --requests 100 --concurrency 10
    python benchmark_vision.py --url http://staging:8001 --requests 50
    python benchmark_vision.py --payload-file payload.json --warmup 5
"""

import asyncio
import argparse
import json
import logging
import statistics
import sys
import time
from typing import Any, Dict, List, Optional

import httpx
from httpx import ASGITransport, AsyncClient


# ---------- Logging Setup ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------- Default Payload ----------
DEFAULT_PAYLOAD = {
    "image_data_b64": "data:image/png;base64,123",
    "url": "http://example.com",
    "title": "login",
}


# ---------- Helper Functions ----------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Vision API Benchmark")
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="Target URL (e.g., http://staging:8001). If not set, uses ASGITransport (in‑process).",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=10,
        help="Total number of requests to send (default: 10).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent requests (default: 10).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Number of warmup requests (default: 1).",
    )
    parser.add_argument(
        "--payload-file",
        type=str,
        default=None,
        help="JSON file containing the request payload.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file (CSV or JSON) for results.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30).",
    )
    return parser.parse_args()


def load_payload(file_path: Optional[str]) -> Dict[str, Any]:
    if file_path:
        with open(file_path, "r") as f:
            return json.load(f)
    return DEFAULT_PAYLOAD


def compute_stats(latencies: List[float]) -> Dict[str, float]:
    if not latencies:
        return {}
    sorted_lat = sorted(latencies)
    return {
        "count": len(latencies),
        "mean": statistics.mean(latencies),
        "median": statistics.median(latencies),
        "p90": latencies[int(len(latencies) * 0.90)],
        "p95": latencies[int(len(latencies) * 0.95)],
        "p99": latencies[int(len(latencies) * 0.99)],
        "min": min(latencies),
        "max": max(latencies),
    }


def print_stats(stats: Dict[str, float]) -> None:
    if not stats:
        return
    print("\n📊 Latency Statistics (ms):")
    print(f"  Requests: {stats['count']}")
    print(f"  Mean:     {stats['mean']:.3f} ms")
    print(f"  Median:   {stats['median']:.3f} ms")
    print(f"  p90:      {stats['p90']:.3f} ms")
    print(f"  p95:      {stats['p95']:.3f} ms")
    print(f"  p99:      {stats['p99']:.3f} ms")
    print(f"  Min:      {stats['min']:.3f} ms")
    print(f"  Max:      {stats['max']:.3f} ms")


def save_results(results: Dict[str, Any], output_path: str) -> None:
    if output_path.endswith(".json"):
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_path}")
    elif output_path.endswith(".csv"):
        import csv
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["latency_ms", "status", "error"])
            for entry in results["details"]:
                writer.writerow([entry["latency"], entry["status"], entry.get("error", "")])
        logger.info(f"Results saved to {output_path}")
    else:
        logger.warning(f"Unsupported output format: {output_path}")


# ---------- Main Benchmark ----------
async def run_benchmark(args: argparse.Namespace) -> None:
    payload = load_payload(args.payload_file)

    # Set up client
    if args.url:
        # Real HTTP endpoint
        client = AsyncClient(base_url=args.url.rstrip("/"), timeout=args.timeout)
        logger.info(f"Target: {args.url}")
    else:
        # In-process ASGITransport
        try:
            from gateway import app
            transport = ASGITransport(app=app)
            client = AsyncClient(transport=transport, base_url="http://testserver", timeout=args.timeout)
            logger.info("Using in-process ASGITransport (gateway.app)")
        except ImportError:
            logger.error("gateway.app not found. Please run this script from the Backend directory.")
            sys.exit(1)

    endpoint = "/vision/analyze"

    # Warmup
    if args.warmup > 0:
        logger.info(f"Warming up with {args.warmup} request(s)...")
        for i in range(args.warmup):
            try:
                resp = await client.post(endpoint, json=payload)
                logger.debug(f"Warmup {i+1}: status={resp.status_code}")
            except Exception as e:
                logger.warning(f"Warmup request {i+1} failed: {e}")
        # Small pause after warmup
        await asyncio.sleep(0.1)

    # Actual benchmark
    total = args.requests
    concurrency = min(args.concurrency, total) if total > 0 else 1
    sem = asyncio.Semaphore(concurrency)
    latencies: List[float] = []
    errors: List[Dict[str, Any]] = []
    success_count = 0
    fail_count = 0

    logger.info(f"Starting benchmark: {total} requests, concurrency={concurrency}...")

    async def make_request(idx: int) -> None:
        nonlocal success_count, fail_count
        async with sem:
            start = time.perf_counter()
            try:
                resp = await client.post(endpoint, json=payload)
                elapsed = (time.perf_counter() - start) * 1000.0  # ms
                latencies.append(elapsed)
                if resp.status_code == 200:
                    success_count += 1
                else:
                    fail_count += 1
                    errors.append({"index": idx, "status": resp.status_code, "latency": elapsed})
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000.0
                fail_count += 1
                errors.append({"index": idx, "error": str(e), "latency": elapsed})

            # Progress every 10%
            if (idx + 1) % max(1, total // 10) == 0:
                pct = (idx + 1) / total * 100
                logger.info(f"Progress: {idx+1}/{total} ({pct:.0f}%)")

    tasks = [make_request(i) for i in range(total)]
    start_total = time.perf_counter()
    await asyncio.gather(*tasks)
    total_time = (time.perf_counter() - start_total) * 1000.0  # ms

    # Close client
    await client.aclose()

    # Compute stats
    stats = compute_stats(latencies)
    stats["throughput_req_per_sec"] = total / (total_time / 1000.0) if total_time > 0 else 0
    stats["success_rate"] = success_count / total * 100 if total > 0 else 0

    # Output
    print(f"\n✅ Benchmark completed in {total_time:.1f} ms")
    print(f"   Success: {success_count} / {total} ({stats['success_rate']:.1f}%)")
    if fail_count > 0:
        print(f"   Failures: {fail_count} (see details below)")

    print_stats(stats)
    print(f"   Throughput: {stats['throughput_req_per_sec']:.2f} req/sec")

    if errors:
        print("\n⚠️  Errors encountered:")
        for err in errors[:5]:  # show first 5
            print(f"   {err}")

    # Save results
    if args.output:
        results = {
            "args": vars(args),
            "stats": stats,
            "details": [
                {"latency": lat, "status": "success"} for lat in latencies
            ] + [
                {"latency": e["latency"], "status": "failed", "error": e.get("error", f"HTTP {e['status']}")}
                for e in errors
            ],
        }
        save_results(results, args.output)


def main():
    args = parse_args()
    try:
        asyncio.run(run_benchmark(args))
    except KeyboardInterrupt:
        logger.info("Benchmark interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()