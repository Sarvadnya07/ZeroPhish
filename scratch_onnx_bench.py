import asyncio
import time
import sys
import numpy as np

sys.path.insert(0, "Backend")
from ml.url_predictor import ONNXURLPredictor

async def main():
    p = ONNXURLPredictor()
    
    # Cold start (first inference including session initialization)
    t0 = time.perf_counter()
    res0 = await p.predict("https://google.com")
    cold_start_ms = (time.perf_counter() - t0) * 1000.0
    
    test_urls = [
        "https://github.com",
        "https://microsoft.com",
        "http://phishing-site-verify-account.com",
        "https://amazon.com",
        "http://paypal-security-update-login.net",
    ]
    
    latencies = []
    for _ in range(20):
        for u in test_urls:
            t = time.perf_counter()
            res = await p.predict(u)
            latencies.append((time.perf_counter() - t) * 1000.0)
            
    arr = np.array(latencies)
    print(f"Cold Start: {cold_start_ms:.3f} ms")
    print(f"Warm Avg:   {np.mean(arr):.3f} ms")
    print(f"Warm Min:   {np.min(arr):.3f} ms")
    print(f"Warm Max:   {np.max(arr):.3f} ms")
    print(f"Warm p50:   {np.percentile(arr, 50):.3f} ms")
    print(f"Warm p95:   {np.percentile(arr, 95):.3f} ms")
    print(f"Warm p99:   {np.percentile(arr, 99):.3f} ms")
    print(f"Iterations: {len(arr)}")

if __name__ == "__main__":
    asyncio.run(main())
