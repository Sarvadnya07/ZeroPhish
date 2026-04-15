import asyncio
import time
from httpx import AsyncClient, ASGITransport
from gateway import app

async def run_benchmark():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Warmup
        data = {"image_data_b64": "data:image/png;base64,123", "url": "http://example.com", "title": "login"}
        res = await client.post("/vision/analyze", json=data)
        print("Warmup status:", res.status_code)

        # Send 10 concurrent requests
        start_time = time.perf_counter()

        async def make_request():
            res = await client.post("/vision/analyze", json=data)
            return res.status_code

        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        print("Results:", set(results))

        end_time = time.perf_counter()
        print(f"Time taken for 10 concurrent requests: {end_time - start_time:.4f} seconds")

if __name__ == "__main__":
    asyncio.run(run_benchmark())
