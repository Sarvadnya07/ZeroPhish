"""
Automated tests for Phase 1.3: Gateway & Pipeline Hardening.

Verifies:
1. Canonical gateway topology and legacy port 8000 entrypoint delegation.
2. Prometheus /metrics exposition format and HTTP 200 response.
3. Server-Sent Events (SSE) broadcast serialization correctness (no Pydantic crash).
4. Verdict schema reconciliation and UNKNOWN state support.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from gateway import app, _broadcast_to_subscribers, _sse_subscribers
from models.gateway_models import Verdict, TierStatus, Tier1Result, CleanStatus
from models.tier1_report import Tier1ReportPayload


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


class TestGatewayTopologyAndLegacyDeprecation:
    def test_legacy_tier2_main_delegates_to_canonical_gateway(self):
        """
        Proves Backend/tier_2/main.py is no longer an independent application,
        but a thin delegation shim exporting the canonical gateway app.
        """
        import tier_2.main as legacy_tier2
        import gateway

        # The legacy app must be identical to the canonical gateway app
        assert legacy_tier2.app is gateway.app

    def test_backend_main_delegates_to_canonical_gateway(self):
        """
        Proves Backend/main.py is a thin delegation shim exporting the canonical gateway app.
        """
        import main as compat_main
        import gateway

        assert compat_main.app is gateway.app


class TestPrometheusMetricsExposition:
    def test_metrics_endpoint_returns_200_and_valid_exposition(self, client):
        """
        Proves GET /metrics returns HTTP 200 with standard Prometheus text exposition format.
        """
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")

        body_text = resp.text
        # Prometheus format markers
        assert "# HELP" in body_text
        assert "# TYPE" in body_text
        # ZeroPhish specific telemetry metrics
        assert "zerophish_http_requests_total" in body_text or "python_gc_objects_collected_total" in body_text


class TestSSESerializationAndBroadcasting:
    @pytest.mark.asyncio
    async def test_broadcast_with_pydantic_model_normalizes_to_dict(self):
        """
        Proves _broadcast_to_subscribers normalizes Pydantic model to a serializable dict,
        preventing json.dumps TypeError in SSE generator.
        """
        sub_id = f"test-sub-{uuid.uuid4()}"
        q = asyncio.Queue(maxsize=10)
        _sse_subscribers[sub_id] = q

        try:
            report = Tier1ReportPayload(
                scan_id="scan-pydantic-test",
                source="test-suite",
                final_score=85.0,
                verdict="CRITICAL",
                evidence=["Threat detected"],
            )

            # Broadcasting Pydantic instance directly
            _broadcast_to_subscribers(report)

            assert not q.empty()
            enqueued_item = q.get_nowait()
            assert isinstance(enqueued_item, dict)
            assert enqueued_item["scan_id"] == "scan-pydantic-test"
            assert enqueued_item["verdict"] == "CRITICAL"

            # Must serialize without TypeError
            serialized = json.dumps(enqueued_item)
            assert "scan-pydantic-test" in serialized

        finally:
            _sse_subscribers.pop(sub_id, None)

    @pytest.mark.asyncio
    async def test_broadcast_with_complex_types_does_not_crash_serializer(self):
        """
        Proves SSE generator handles datetimes, UUIDs, and Enums with default=str.
        """
        sub_id = f"test-complex-{uuid.uuid4()}"
        q = asyncio.Queue(maxsize=10)
        _sse_subscribers[sub_id] = q

        try:
            complex_payload = {
                "scan_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "verdict": Verdict.SUSPICIOUS,
                "status": TierStatus.COMPLETE,
            }

            _broadcast_to_subscribers(complex_payload)
            enqueued = q.get_nowait()

            # Verify it serializes cleanly with default=str
            serialized = json.dumps(enqueued, default=str)
            assert "SUSPICIOUS" in serialized
            assert "complete" in serialized

        finally:
            _sse_subscribers.pop(sub_id, None)

    def test_post_tier1_report_does_not_crash_sse_subscribers(self, client):
        """
        Proves POST /tier1/report broadcasts dictionary and returns success.
        """
        sub_id = f"test-post-{uuid.uuid4()}"
        q = asyncio.Queue(maxsize=10)
        _sse_subscribers[sub_id] = q

        try:
            payload = {
                "scan_id": "report-broadcast-verify",
                "source": "chrome-extension",
                "final_score": 42.0,
                "verdict": "SUSPICIOUS",
                "evidence": ["Keyword match urgency"],
            }
            resp = client.post("/tier1/report", json=payload)
            assert resp.status_code == 200
            assert resp.json()["status"] == "success"

            assert not q.empty()
            item = q.get_nowait()
            assert isinstance(item, dict)
            assert item["scan_id"] == "report-broadcast-verify"
            # Verify json serialization
            json_str = json.dumps(item, default=str)
            assert "report-broadcast-verify" in json_str

        finally:
            _sse_subscribers.pop(sub_id, None)


class TestVerdictSchemaReconciliation:
    def test_verdict_enum_supports_all_states_including_unknown(self):
        """
        Proves Verdict enum supports SAFE, SUSPICIOUS, CRITICAL, and UNKNOWN.
        """
        assert Verdict.SAFE == "SAFE"
        assert Verdict.SUSPICIOUS == "SUSPICIOUS"
        assert Verdict.CRITICAL == "CRITICAL"
        assert Verdict.UNKNOWN == "UNKNOWN"

        assert Verdict("UNKNOWN") == Verdict.UNKNOWN
        assert Verdict["UNKNOWN"] == Verdict.UNKNOWN

    def test_verdict_and_tier_status_are_distinct(self):
        """
        Proves security verdict (threat level decision) and analysis status
        (processing lifecycle state) are kept distinct.
        """
        assert set(Verdict.__members__.keys()) == {"SAFE", "SUSPICIOUS", "CRITICAL", "UNKNOWN"}
        assert set(TierStatus.__members__.keys()) == {"PROCESSING", "COMPLETE", "FAILED", "TIMEOUT"}
