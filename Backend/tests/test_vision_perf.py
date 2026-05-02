import pytest
import time
from httpx import AsyncClient, ASGITransport
from gateway import app

@pytest.mark.asyncio
async def test_vision_performance():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        data = {"image_data_b64": "data:image/png;base64,123", "url": "http://example.com", "title": "login"}

        start_time = time.perf_counter()
        import asyncio
        tasks = [client.post("/vision/analyze", json=data) for _ in range(5)]
        results = await asyncio.gather(*tasks)
        end_time = time.perf_counter()

        # It should take roughly 0.3s if concurrent, but 1.5s if sequential
        duration = end_time - start_time
        assert duration < 1.0, f"Requests took too long: {duration}s"
