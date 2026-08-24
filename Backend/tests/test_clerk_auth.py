"""
Unit & Integration Tests for Clerk Authentication & RBAC Authorization in ZeroPhish.
"""

import time
from fastapi.testclient import TestClient
import jwt
import pytest

from auth.models import UserRole, UserStatus, UserUpdate
from auth.service import AuthService, _users_by_clerk_id, _users_by_email, _users_by_id
from gateway import app


from repositories.factory import reset_repositories


@pytest.fixture(autouse=True)
def reset_auth_state(monkeypatch):
    reset_repositories()
    _users_by_id.clear()
    _users_by_email.clear()
    _users_by_clerk_id.clear()
    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "true")
    yield
    reset_repositories()


@pytest.fixture
def client():
    return TestClient(app)


def test_missing_token_returns_401(client):
    """Accessing protected endpoint without token returns 401."""
    res = client.get("/auth/me")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]


def test_invalid_token_returns_401(client, monkeypatch):
    """Malformed token returns 401."""
    monkeypatch.setenv("ZEROPHISH_TEST_AUTH", "false")
    res = client.get("/auth/me", headers={"Authorization": "Bearer not-a-valid-jwt"})
    assert res.status_code == 401


def test_valid_clerk_token_provisions_user_with_user_role(client):
    """Valid Clerk token provisions a new user with default USER role."""
    token = "test_token_alice_user"
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["clerk_user_id"] == "user_clerk_alice"
    assert data["email"] == "alice@example.com"
    assert data["role"] == "user"
    assert data["status"] == "active"


def test_regular_user_denied_admin_endpoints(client):
    """Standard user is denied access to /admin/users (403 Forbidden)."""
    token = "test_token_bob_user"
    res = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "Requires one of roles" in res.json()["detail"]


def test_admin_user_can_access_admin_endpoints_and_manage_roles(client, monkeypatch):
    """Admin user can list users and update roles."""
    monkeypatch.setenv("CLERK_ADMIN_USER_IDS", "user_clerk_admin1")

    # 1. Admin logs in
    admin_token = "test_token_admin1_admin"
    admin_me = client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_me.status_code == 200
    assert admin_me.json()["role"] == "admin"

    # 2. Regular user logs in
    user_token = "test_token_charlie_user"
    user_me = client.get("/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert user_me.status_code == 200
    user_id = user_me.json()["id"]
    assert user_me.json()["role"] == "user"

    # 3. Admin lists users
    list_res = client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert list_res.status_code == 200
    users = list_res.json()
    assert len(users) >= 2

    # 4. Admin promotes Charlie to Analyst
    patch_res = client.patch(
        f"/admin/users/{user_id}",
        json={"role": "analyst"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["role"] == "analyst"

    # 5. Charlie now has analyst role
    charlie_me = client.get("/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert charlie_me.status_code == 200
    assert charlie_me.json()["role"] == "analyst"


def test_update_me_allows_name_change(client):
    """User can update their full_name via /auth/me."""
    token = "test_token_dana_user"
    client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    patch_res = client.patch(
        "/auth/me",
        json={"full_name": "Dana Cybersecurity", "role": "admin"},  # role modification should be ignored
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["full_name"] == "Dana Cybersecurity"
    assert data["role"] == "user"  # Role remained unchanged
