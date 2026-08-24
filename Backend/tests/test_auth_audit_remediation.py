"""
Test suite for ZeroPhish Authentication Audit & Security Remediation.
Verifies least-privilege user provisioning, CORS preflight validation,
and RBAC enforcement under Clerk identity architecture.
"""

import pytest
from fastapi.testclient import TestClient

from auth.models import UserRole
from auth.service import AuthService, _users_by_clerk_id, _users_by_email, _users_by_id
from gateway import app


@pytest.fixture(autouse=True)
def reset_auth_state(monkeypatch):
    _users_by_id.clear()
    _users_by_email.clear()
    _users_by_clerk_id.clear()
    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_cors_preflight_for_frontend_origin(client):
    """Ensure preflight OPTIONS requests from http://localhost:3000 pass CORS."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    res = client.options("/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert res.headers.get("access-control-allow-credentials") == "true"


def test_first_login_provisions_with_least_privilege_user_role(client):
    """Ensure public logins always start with UserRole.USER (least privilege)."""
    token = "test_token_newuser_user"
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == UserRole.USER.value


def test_unauthenticated_request_rejected(client):
    """Ensure requests without Bearer token are rejected."""
    res = client.get("/auth/me")
    assert res.status_code == 401
