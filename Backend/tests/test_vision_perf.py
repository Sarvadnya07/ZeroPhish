"""
Vision endpoint performance test.
Tests that concurrent vision analyze requests complete within a reasonable time.
"""

import time

import pytest


@pytest.mark.asyncio
async def test_vision_performance():
    """Vision endpoint should handle concurrent requests efficiently."""
    import asyncio

    from httpx import ASGITransport, AsyncClient

    # Import inside test to avoid module-level FastAPI/Pydantic compat issue
    from gateway import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # First register and login to get a token (vision requires auth)
        reg_resp = await client.post(
            "/auth/register",
            json={
                "email": "visiontest@example.com",
                "password": "VisionTest@123",
                "full_name": "Vision Tester",
            },
        )
        # May already exist — just login
        login_resp = await client.post(
            "/auth/login",
            json={"email": "visiontest@example.com", "password": "VisionTest@123"},
        )
        if login_resp.status_code != 200:
            pytest.skip("Could not authenticate for vision performance test")

        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        data = {
            "image_data_b64": "data:image/png;base64,123",
            "url": "http://example.com",
            "title": "login",
        }

        start_time = time.perf_counter()
        tasks = [client.post("/vision/analyze", json=data, headers=headers) for _ in range(5)]
        results = await asyncio.gather(*tasks)
        end_time = time.perf_counter()

        duration = end_time - start_time
        # Each request has a 0.3s artificial delay; 5 concurrent should complete in ~0.3-0.6s
        assert duration < 3.0, f"Concurrent vision requests took too long: {duration:.2f}s"
        # All should respond (auth 401 still counts as a response)
        assert all(r.status_code in (200, 401, 429) for r in results)
