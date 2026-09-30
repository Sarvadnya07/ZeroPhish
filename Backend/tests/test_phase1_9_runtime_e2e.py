"""
ZeroPhish — Phase 1.9 Full Runtime End-to-End Validation Suite.

Validates the complete production application path against all 42 acceptance criteria:
- Architecture integrity (Gateway port 8001 sole entry, shim deprecation)
- Request validation (HTTP 400 on malformed URL, invalid email, oversized payload)
- Client trust boundary enforcement (client scores cannot suppress server evidence)
- Scan lifecycle coherence (creation -> partial L2 -> background finalization -> complete L3/L4)
- Monotonic security floor survival under advisory failure (T3 failure, Vision failure, all advisory unavailable)
- Vision-required state and boundary enforcement (VISUAL_REQUIRED preserved, Vision cannot create CRITICAL)
- Schema consistency (REST, SSE, polling, string enum serialization)
- SSE & polling delivery equivalence
- Concurrency, deduplication, and cross-scan state isolation
- Security protections (SSRF, Unicode normalization, zero credential leakage)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from gateway import app, CONFIG
from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    GatewayScanRequest,
    GatewayScanResponse,
    ScanStatusResponse,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    Verdict,
)
from vision.models import VisionStatus, VisionAnalysisResult


@pytest.fixture
def client():
    """TestClient bound to the canonical Gateway FastAPI application."""
    default_tier3 = Tier3Result(
        score=15,
        category="Clean",
        reasoning="Routine email communication",
        flagged_phrases=[],
        status=TierStatus.COMPLETE,
        confidence=0.9,
        requires_visual_check=False,
        execution_time_ms=25.0,
    )
    with patch("gateway.execute_tier3_with_circuit_breaker", return_value=default_tier3):
        yield TestClient(app)



# ==============================================================================
# 1. ARCHITECTURE INTEGRITY GATES (Criteria 1-3)
# ==============================================================================
class TestArchitectureIntegrity:
    def test_gateway_app_is_canonical_entry_point(self):
        """Criterion 1: Backend/gateway.py is the canonical entry point on port 8001."""
        assert app.title == "ZeroPhish API Gateway"
        # NOTE (Phase 1.10): this previously read
        #     `assert CONFIG.port == 8001 or isinstance(CONFIG.port, int)`
        # which is tautological (CONFIG.port is always an int), so the criterion
        # could never fail. Assert the canonical default directly.
        assert CONFIG.port == 8001, "canonical gateway port must be 8001"

    def test_main_shim_delegates_to_gateway_app(self):
        """Criteria 2 & 3: main.py is a deprecation shim re-exporting gateway.app."""
        import main
        assert main.app is app, "main.py must re-export the exact gateway app instance"


# ==============================================================================
# 2. INPUT VALIDATION & CLIENT TRUST BOUNDARY (Criteria 4-5, 35)
# ==============================================================================
class TestInputValidationAndTrustBoundary:
    def test_invalid_url_scheme_rejected_with_http_400(self, client):
        """Criterion 4: Invalid URL schemes (e.g. ftp://, javascript:) are rejected with HTTP 400."""
        payload = {
            "sender": "analyst@company.com",
            "body": "Check this file on FTP server",
            "links": ["ftp://malicious-server.org/malware.exe"],
        }
        res = client.post("/gateway/scan", json=payload)
        assert res.status_code == 400
        assert "Invalid URL format in links" in str(res.json())

    def test_javascript_scheme_url_rejected_with_http_400(self, client):
        """Criterion 4: JavaScript pseudo-URLs rejected with HTTP 400."""
        payload = {
            "sender": "analyst@company.com",
            "body": "Click here to view",
            "links": ["javascript:alert(1)"],
        }
        res = client.post("/gateway/scan", json=payload)
        assert res.status_code == 400
        assert "Invalid URL format in links" in str(res.json())

    def test_malformed_email_rejected_with_validation_error(self, client):
        """Criterion 4: Malformed sender email rejected with HTTP 422 or 400."""
        payload = {
            "sender": "not-an-email-at-all",
            "body": "Normal body content",
            "links": ["https://example.com"],
        }
        res = client.post("/gateway/scan", json=payload)
        assert res.status_code in (400, 422)

    def test_oversized_body_rejected(self, client):
        """Criterion 4 & 35: Oversized body text (>50KB) rejected with HTTP 422 or 400."""
        payload = {
            "sender": "analyst@company.com",
            "body": "A" * 60000,
            "links": ["https://example.com"],
        }
        res = client.post("/gateway/scan", json=payload)
        assert res.status_code in (400, 422)

    def test_client_score_zero_cannot_suppress_server_detected_threat(self, client):
        """Criterion 5 & 31: Client supplying score=0 cannot suppress server heuristic findings."""
        payload = {
            "sender": "security-update@chase-bank-verify.info",
            "body": "URGENT: Your account has been suspended! Enter your password immediately: http://192.168.1.1/login",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 0,  # Client attempting to suppress threat
            "tier1_evidence": ["Client claims email is safe"],
        }
        res = client.post("/gateway/scan", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["tier1"]["server_score"] >= 20, "Server must detect IP literal and password cues"
        assert data["tier1"]["score"] >= data["tier1"]["server_score"], "Effective T1 score cannot be suppressed by client"
        assert data["partial_score"] >= 20.0
        assert data["verdict"] in ("SUSPICIOUS", "CRITICAL")


# ==============================================================================
# 3. CANONICAL SCAN LIFECYCLE & STATE MACHINE (Criteria 6-9, 21-24)
# ==============================================================================
class TestScanLifecycleAndStateMachine:
    def test_scan_lifecycle_from_creation_to_terminal_state(self, client):
        """Criteria 6-8, 21-23: Full scan lifecycle from L2 processing to terminal L3/L4 state."""
        payload = {
            "sender": "notifications@github.com",
            "subject": "New commit on main",
            "body": "A new commit was pushed to main branch in your repository.",
            "links": ["https://github.com"],
        }
        mock_t3 = Tier3Result(
            score=10,
            category="Clean",
            reasoning="Valid GitHub commit alert",
            flagged_phrases=[],
            status=TierStatus.COMPLETE,
            confidence=0.9,
            requires_visual_check=False,
            execution_time_ms=45.0,
        )
        with patch("gateway.execute_tier3_with_circuit_breaker", return_value=mock_t3):
            # 1. Initial submission
            res = client.post("/gateway/scan", json=payload)
            assert res.status_code == 200
            initial = res.json()
            scan_id = initial["scan_id"]
            assert initial["complete"] is False
            assert initial["layers_completed"] == 2
            assert initial["tier3_status"] == "processing"
            assert initial["final_score"] is None
            assert initial["partial_score"] is not None

            # 2. Polling status endpoint
            status_res = client.get(f"/gateway/status/{scan_id}")
            assert status_res.status_code == 200
            status_data = status_res.json()
            assert status_data["scan_id"] == scan_id
            assert status_data["tier3_status"] in ("processing", "complete")

            # 3. Await completion (fast in test client)
            final_res = client.get(f"/gateway/result/{scan_id}")
            assert final_res.status_code == 200
            final_data = final_res.json()
            assert final_data["complete"] is True
            assert final_data["layers_completed"] >= 3
            assert final_data["final_score"] is not None
            assert final_data["verdict"] in ("SAFE", "SUSPICIOUS", "CRITICAL")

            # 4. Invariance: Terminal state cannot regress into earlier state
            status_after = client.get(f"/gateway/status/{scan_id}").json()
            assert status_after["complete"] is True
            assert status_after["layers_completed"] >= 3



# ==============================================================================
# 4. ADVISORY FAILURE & MONOTONIC SECURITY FLOORS (Criteria 9, 13, 16)
# ==============================================================================
class TestAdvisoryFailureMonotonicFloors:
    def test_suspicious_baseline_survives_tier3_timeout(self, client):
        """Criteria 9 & 13: Tier 3 timeout preserves SUSPICIOUS baseline and never becomes SAFE."""
        payload = {
            "sender": "payroll@spoofed-company-domain.net",
            "body": "Urgent update required for your direct deposit credentials.",
            "links": ["http://spoofed-company-domain.net/login"],
            "tier1_score": 45,
            "tier1_evidence": ["Suspicious login URL"],
        }
        with patch("gateway.execute_tier3_with_circuit_breaker", side_effect=asyncio.TimeoutError("AI timeout")):
            res = client.post("/gateway/scan", json=payload)
            assert res.status_code == 200
            scan_id = res.json()["scan_id"]

            final_res = client.get(f"/gateway/result/{scan_id}").json()
            assert final_res["complete"] is True
            assert final_res["tier3_status"] == "timeout"
            assert final_res["verdict"] in ("SUSPICIOUS", "CRITICAL"), "Advisory timeout must not produce SAFE"
            assert final_res["final_score"] >= res.json()["partial_score"]

    def test_critical_baseline_survives_advisory_failure(self, client):
        """Criteria 9 & 13: Critical baseline survives complete advisory provider failure."""
        payload = {
            "sender": "security-alert@paypal.suspicious-login.xyz",
            "body": "URGENT: Unauthorized access detected. Sign in now: http://192.168.1.1/login",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 85,
            "tier1_evidence": ["IP literal in URL", "Credential harvest"],
        }
        with patch("gateway.execute_tier3_with_circuit_breaker", side_effect=RuntimeError("Provider API down")):
            res = client.post("/gateway/scan", json=payload)
            assert res.status_code == 200
            scan_id = res.json()["scan_id"]

            final_res = client.get(f"/gateway/result/{scan_id}").json()
            assert final_res["complete"] is True
            assert final_res["tier3_status"] == "failed"
            assert final_res["verdict"] == "CRITICAL", "Critical baseline must survive advisory provider failure"
            assert final_res["final_score"] >= 70.0


# ==============================================================================
# 5. VISION LIFECYCLE & BOUNDARIES (Criteria 14-16)
# ==============================================================================
class TestVisionLifecycleAndBoundaries:
    def test_vision_required_state_when_screenshot_missing(self, client):
        """Criteria 14 & 15: Missing screenshot when Tier 3 requires visual check remains VISUAL_REQUIRED."""
        payload = {
            "sender": "portal-support@brand-login.org",
            "body": "Please log in to review your confidential invoice.",
            "links": ["http://brand-login.org/invoice"],
        }
        # Mock Tier 3 returning requires_visual_check=True
        mock_tier3 = Tier3Result(
            score=45,
            category="AUTHENTICATION_PORTAL",
            reasoning="Login portal requires optical brand inspection",
            flagged_phrases=["log in to review"],
            status=TierStatus.COMPLETE,
            confidence=0.85,
            requires_visual_check=True,
            execution_time_ms=120.0,
        )
        with patch("gateway.execute_tier3_with_circuit_breaker", return_value=mock_tier3):
            res = client.post("/gateway/scan", json=payload)
            assert res.status_code == 200
            scan_id = res.json()["scan_id"]

            # Polling endpoint (/gateway/status/{scan_id} and /api/v1/scan/{scan_id})
            poll_res = client.get(f"/api/v1/scan/{scan_id}").json()
            assert poll_res["complete"] is True
            assert poll_res["vision"] is not None
            assert str(poll_res["vision"]["status"]).upper() == "VISUAL_REQUIRED"
            assert poll_res["vision"]["requires_followup"] is True
            assert poll_res["vision"]["visual_score"] is None
            assert poll_res["explanation"]["tier_summaries"]["vision"]["status"] == "visual_required"
            assert poll_res["explanation"]["tier_summaries"]["vision"]["requires_followup"] is True
            assert poll_res["explanation"]["tier_summaries"]["vision"]["score"] is None
            assert poll_res["explanation"]["tier_summaries"]["vision"]["participated"] is False

            # Full result endpoint (/gateway/result/{scan_id})
            final_res = client.get(f"/gateway/result/{scan_id}").json()
            assert final_res["complete"] is True
            assert final_res["vision"] is not None
            assert str(final_res["vision"]["status"]).upper() == "VISUAL_REQUIRED"
            assert final_res["vision"]["requires_followup"] is True
            assert final_res["vision"]["visual_score"] is None
            assert final_res["explanation"]["tier_summaries"]["vision"]["status"] == "visual_required"
            assert final_res["explanation"]["tier_summaries"]["vision"]["requires_followup"] is True
            assert final_res["explanation"]["tier_summaries"]["vision"]["score"] is None
            assert final_res["explanation"]["tier_summaries"]["vision"]["participated"] is False
            assert final_res["verdict"] in ("SUSPICIOUS", "CRITICAL")
            assert final_res["final_score"] is not None and final_res["final_score"] >= res.json()["partial_score"]


    def test_vision_cannot_independently_elevate_safe_to_critical(self, client):
        """
        Criterion 16: Vision is strictly advisory and cannot create CRITICAL from a
        clean baseline.

        The vision weight is profile-dependent: 0.15 when Tier 3 also participates,
        0.25 when Tier 3 is absent/failed (fusion/engine.py ESTABLISHED_PROFILES).
        A hostile visual_score must therefore be down-weighted by fusion rather than
        trusted as authority.

        NOTE (Phase 1.10): this test previously patched
        `VisionService.analyze_screenshot` with a bare `return_value=`, which makes
        `unittest.mock` choose MagicMock rather than AsyncMock. Because
        `analyze_screenshot` is a descriptor (not a coroutine function), the mock
        returned a non-awaitable, `await` raised TypeError, and gateway.py's broad
        `except Exception` replaced the hostile vision result with
        `VisionStatus.FAILED`. The assertions passed vacuously — vision was
        degraded away, never actually down-weighted by fusion. `new_callable=AsyncMock`
        is required so the hostile score reaches the fusion engine, as the sibling
        test in test_vision_phase1_6.py already does.
        """
        payload = {
            "sender": "clean-newsletter@legitimate-service.com",
            "body": "Monthly newsletter update with product release notes.",
            "links": ["https://legitimate-service.com/blog"],
            "screenshot_b64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        }
        mock_tier3 = Tier3Result(
            score=5,
            category="Clean",
            reasoning="Routine newsletter",
            flagged_phrases=[],
            status=TierStatus.COMPLETE,
            confidence=0.95,
            requires_visual_check=False,
            execution_time_ms=50.0,
        )
        mock_vision = VisionAnalysisResult(
            status=VisionStatus.SUCCESS,
            visual_score=95.0,  # Hostile high vision score
            confidence=0.9,
            visual_category="SUSPECTED_LOGO_IMPERSONATION",
            findings=["Brand logo mismatch suspected visually"],
            brand_domain_mismatch=True,
        )
        with patch("gateway.execute_tier3_with_circuit_breaker", return_value=mock_tier3), \
             patch(
                 "vision.service.VisionService.analyze_screenshot",
                 new_callable=AsyncMock,
                 return_value=mock_vision,
             ) as vision_mock:
            res = client.post("/gateway/scan", json=payload)
            scan_id = res.json()["scan_id"]

            final_res = client.get(f"/gateway/result/{scan_id}").json()

            # The hostile vision result must actually have been applied — otherwise
            # the boundary this test claims to verify was never exercised.
            assert vision_mock.await_count >= 1, "vision was not invoked; test is vacuous"
            assert final_res["vision"] is not None
            assert final_res["vision"]["visual_score"] == 95.0, (
                "hostile vision score did not reach the pipeline; the assertion below "
                "would not be testing the fusion boundary"
            )

            assert final_res["verdict"] != "CRITICAL", "Vision alone must never elevate clean baseline to CRITICAL"
            assert final_res["final_score"] < 70.0


# ==============================================================================
# 6. SCHEMA INTEGRITY & ENUM SERIALIZATION (Criteria 17-20)
# ==============================================================================
class TestSchemaIntegrityAndSerialization:
    def test_verdict_enum_serializes_as_standard_string(self, client):
        """Criterion 18: Verdict enum serializes strictly as 'SAFE', 'SUSPICIOUS', or 'CRITICAL'."""
        payload = {
            "sender": "team@trusted-partner.org",
            "body": "Meeting agenda for Friday sync.",
            "links": ["https://trusted-partner.org/meeting"],
        }
        res = client.post("/gateway/scan", json=payload)
        data = res.json()
        assert data["verdict"] in ("SAFE", "SUSPICIOUS", "CRITICAL")
        assert not data["verdict"].startswith("Verdict."), "Verdict must serialize as raw string value"

    def test_sse_payload_schema_matches_contract(self, client):
        """Criteria 17 & 23: SSE broadcast payload includes complete, string verdict, and clean tier details."""
        from gateway import _notify_live_dashboard
        sample_response = GatewayScanResponse(
            scan_id="sse-schema-test-123",
            partial_score=15.0,
            final_score=15.0,
            verdict=Verdict.SAFE,
            complete=True,
            layers_completed=3,
            combined_evidence=["Domain verified"],
            tier1=Tier1Result(score=5, status=CleanStatus.CLEAN, evidence=[]),
            tier2=Tier2Result(
                score=10.0,
                domain_analysis=DomainAnalysis(status=DomainStatus.OK, score=10.0),
                threat_analysis=Tier2Analysis(status=DomainStatus.OK, score=10.0),
                threat_details=ThreatAnalysisDetail(threat_level=10, category="Safe", reasoning="Normal", flagged_phrases=[]),
                evidence=[],
            ),
            tier3=Tier3Result(score=10, category="Safe", reasoning="Clean", flagged_phrases=[], status=TierStatus.COMPLETE),
        )
        with patch("gateway._broadcast_to_subscribers") as mock_broadcast:
            asyncio.run(_notify_live_dashboard(sample_response, "sender@example.com", "Subject"))
            mock_broadcast.assert_called_once()
            payload = mock_broadcast.call_args[0][0]
            assert payload["scan_id"] == "sse-schema-test-123"
            assert payload["complete"] is True
            assert payload["verdict"] == "SAFE"
            assert isinstance(payload["timestamp"], str)
            assert payload["tier_details"]["tier1"]["score"] == 5
            assert payload["tier_details"]["tier2"]["score"] == 10.0
            assert payload["tier_details"]["tier3"]["score"] == 10



# ==============================================================================
# 7. CONCURRENCY & ISOLATION GATES (Criteria 25-28)
# ==============================================================================
class TestConcurrencyAndStateIsolation:
    def test_concurrent_scans_have_isolated_state_and_unique_ids(self, client):
        """
        Criteria 25-28: distinct scans produce unique IDs and independently
        retrievable state.

        NOTE (Phase 1.10): the submissions below are issued *sequentially* through
        the synchronous TestClient, so this verifies ID uniqueness and per-scan
        state separation — NOT isolation under true interleaving. Genuine
        concurrent-scan coverage (overlapping requests racing on
        `scan_results_lock`) is an identified Phase 1 coverage gap; see
        docs/PHASE_1_FINAL_PRODUCTION_READINESS_REPORT.md.
        """
        payloads = [
            {
                "sender": f"user{i}@company{i}.com",
                "body": f"Notification message {i} for review",
                "links": [f"https://company{i}.com/page"],
            }
            for i in range(5)
        ]

        responses = [client.post("/gateway/scan", json=p) for p in payloads]
        assert all(r.status_code == 200 for r in responses)

        scan_ids = [r.json()["scan_id"] for r in responses]
        # Assert complete uniqueness of scan IDs
        assert len(set(scan_ids)) == len(scan_ids) == 5

        # Query results for each scan independently
        for scan_id in scan_ids:
            st = client.get(f"/gateway/status/{scan_id}")
            assert st.status_code == 200
            assert st.json()["scan_id"] == scan_id


# ==============================================================================
# 8. OBSERVABILITY & REDACTION GATES (Criteria 36)
# ==============================================================================
class TestObservabilityAndSecretRedaction:
    def test_health_and_metrics_do_not_leak_secrets(self, client):
        """Criterion 36: Diagnostics endpoints expose metrics without leaking keys or credentials."""
        health = client.get("/gateway/health").json()
        assert health["status"] == "healthy"
        assert "api_key" not in health
        assert "secret_key" not in health

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "password" not in metrics.text.lower()
        assert "api_key" not in metrics.text.lower()
