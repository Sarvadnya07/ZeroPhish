"""
Tests for gateway live SSE endpoints, health status, and circuit breaker endpoints.
"""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from gateway import app


@pytest.fixture
def client():
    return TestClient(app)


def test_gateway_health_endpoint(client):
    """Test /gateway/health returns full diagnostics."""
    response = client.get("/gateway/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "weights" in data
    assert "scans" in data


def test_gateway_circuit_endpoints(client):
    """Test circuit status and reset endpoints."""
    resp = client.get("/gateway/circuit/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data or "enabled" in data

    resp_reset = client.post("/gateway/circuit/reset")
    assert resp_reset.status_code == 200


def test_gateway_tier1_report_and_latest(client):
    """Test /tier1/report and /tier1/latest."""
    sample_report = {
        "scan_id": "test-sse-1",
        "sender": "sender@phish.com",
        "subject": "Urgent update",
        "final_score": 92.0,
        "verdict": "CRITICAL",
        "timestamp": "2026-01-01T00:00:00Z",
    }

    # Submit report
    resp_post = client.post("/tier1/report", json=sample_report)
    assert resp_post.status_code == 200
    assert resp_post.json()["status"] == "success"

    # Get latest
    resp_latest = client.get("/tier1/latest")
    assert resp_latest.status_code == 200
    latest_data = resp_latest.json()
    assert latest_data["scan_id"] == "test-sse-1"
    assert latest_data["verdict"] == "CRITICAL"
