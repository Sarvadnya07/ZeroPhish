"""
Vision endpoint performance test.
Tests that concurrent vision analyze requests complete within a reasonable time,
and that multimodal vision flow processes responses correctly.
"""

import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tier_3.base import ProviderExecutionStatus, ProviderRawResponse


@pytest.mark.asyncio
async def test_vision_performance(monkeypatch):
    """Vision endpoint should handle concurrent requests efficiently."""
    import asyncio
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
    from gateway import app

    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "mock_key_for_test")

    mock_raw = ProviderRawResponse(
        provider_id="gemini",
        model="gemini-1.5-flash",
        status=ProviderExecutionStatus.SUCCESS,
        raw_text=json.dumps({
            "visual_score": 92.5,
            "confidence": 0.95,
            "visual_category": "AUTHENTICATION_PORTAL",
            "findings": ["Detected fraudulent Office 365 sign-in clone."],
            "detected_brands": ["Microsoft"],
            "visual_brand_confidence": 0.95,
            "credential_ui_detected": True,
            "payment_ui_detected": False,
            "visual_impersonation_signal": True,
            "detected_elements": [{"class_name": "fake_login_form", "confidence": 0.95}],
        }),
    )

    with patch("tier_3.router.Tier3Router.has_available_provider", return_value=True):
        with patch("tier_3.router.Tier3Router.route_and_execute_multimodal", new_callable=AsyncMock, return_value=mock_raw):
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
                assert body["status"] == "SUCCESS"
                assert body["visual_score"] == 92.5
                assert "Microsoft" in body["detected_brands"]
                assert body["brand_domain_mismatch"] is True
                assert body["matched_brand"] == "Microsoft"
                assert body["threat_score"] == 92.5
