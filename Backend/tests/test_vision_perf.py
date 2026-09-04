"""
Vision endpoint performance test.
Tests that concurrent vision analyze requests complete within a reasonable time.
"""

import time

import pytest


@pytest.mark.asyncio
async def test_vision_performance(monkeypatch):
    """Vision endpoint should handle concurrent requests efficiently."""
    import asyncio

    from httpx import ASGITransport, AsyncClient

    # Import inside test to avoid module-level FastAPI/Pydantic compat issue
    from gateway import app

    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        token = "test_token_vision_user"
        headers = {"Authorization": f"Bearer {token}"}

        # Valid 1x1 PNG base64 payload (110 bytes)
        data = {
            "image_data_b64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
            "url": "http://example.com",
            "title": "login",
        }

        start_time = time.perf_counter()
        tasks = [client.post("/vision/analyze", json=data, headers=headers) for _ in range(5)]
        results = await asyncio.gather(*tasks)
        end_time = time.perf_counter()

        duration = end_time - start_time
        assert duration < 5.0, f"Concurrent vision requests took too long: {duration:.2f}s"
        assert all(r.status_code in (200, 429) for r in results)


@pytest.mark.asyncio
async def test_vision_gemini_path_mocked(monkeypatch):
    """Verify vision endpoint correctly handles Gemini model output when configured."""
    from unittest.mock import MagicMock, patch
    from httpx import ASGITransport, AsyncClient
    from gateway import app

    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "mock_key_for_test")

    mock_gemini_result = {
        "is_phishing": True,
        "threat_score": 92.5,
        "detected_elements": [{"class_name": "fake_login_form", "confidence": 0.95}],
        "matched_brand": "microsoft",
        "reasoning": "Detected fraudulent Office 365 sign-in clone.",
        "processing_time_ms": 42.0,
    }

    with patch("vision.service.VisionService._analyze_with_gemini", return_value=mock_gemini_result):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            token = "test_token_vision_user"
            headers = {"Authorization": f"Bearer {token}"}
            data = {
                "image_data_b64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                "url": "http://fake-office-login.com",
                "title": "Sign in to Microsoft Online",
            }
            res = await client.post("/vision/analyze", json=data, headers=headers)
            assert res.status_code == 200
            body = res.json()
            assert body["is_phishing"] is True
            assert body["threat_score"] == 92.5
            assert body["matched_brand"] == "microsoft"
