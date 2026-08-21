import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Import gateway inside fixture to avoid module-level FastAPI/Pydantic compat issue."""
    from gateway import app
    return TestClient(app)


@pytest.fixture
def mock_api_key_env():
    """Mock the API_KEY environment variable."""
    with patch.dict(os.environ, {"API_KEY": "test_secure_api_key_123"}):
        yield


@pytest.fixture
def mock_no_api_key_env():
    """Ensure API_KEY environment variable is not set."""
    with patch.dict(os.environ, {"API_KEY": ""}):
        yield


def test_gateway_endpoints_require_api_key(client, mock_api_key_env):
    """Test that endpoints return 403 when API key is required but missing."""
    scan_data = {
        "sender": "test@example.com",
        "body": "Test body",
        "links": [],
        "tier1_score": 10,
        "tier1_evidence": [],
    }
    response = client.post("/gateway/scan", json=scan_data)
    assert response.status_code == 403
    assert response.json()["detail"] == "Could not validate API key"

    response = client.get("/gateway/status/dummy-id")
    assert response.status_code == 403

    response = client.get("/gateway/result/dummy-id")
    assert response.status_code == 403


def test_gateway_endpoints_accept_valid_api_key(client, mock_api_key_env):
    """Test that endpoints accept a valid API key."""
    headers = {"X-API-Key": "test_secure_api_key_123"}

    scan_data = {
        "sender": "test@example.com",
        "body": "Test body",
        "links": [],
        "tier1_score": 10,
        "tier1_evidence": [],
    }
    response = client.post("/gateway/scan", json=scan_data, headers=headers)
    assert response.status_code == 200
    assert "scan_id" in response.json()

    scan_id = response.json()["scan_id"]

    response = client.get(f"/gateway/status/{scan_id}", headers=headers)
    assert response.status_code == 200

    response = client.get(f"/gateway/result/{scan_id}", headers=headers)
    assert response.status_code == 200


def test_gateway_endpoints_work_without_api_key_env(client, mock_no_api_key_env):
    """Test that endpoints work without an API key if API_KEY is not set."""
    scan_data = {
        "sender": "test@example.com",
        "body": "Test body",
        "links": [],
        "tier1_score": 10,
        "tier1_evidence": [],
    }
    response = client.post("/gateway/scan", json=scan_data)
    assert response.status_code == 200
    assert "scan_id" in response.json()

    scan_id = response.json()["scan_id"]

    response = client.get(f"/gateway/status/{scan_id}")
    assert response.status_code == 200

    response = client.get(f"/gateway/result/{scan_id}")
    assert response.status_code == 200
