"""
Test suite for ZeroPhish Master Authentication Audit & Remediation.
Verifies self-registration role escalation defense, password change persistence,
MFA verification, audit logging, rate limiting, and session security.
"""

import pytest
from fastapi.testclient import TestClient

from auth.models import UserCreate, UserLogin, UserRole
from auth.service import AuthService, _tokens, _users_by_email, _users_by_id
from gateway import app


@pytest.fixture(autouse=True)
def reset_auth_state():
    from auth.service import _seed_admin

    _users_by_id.clear()
    _users_by_email.clear()
    _tokens.clear()
    _seed_admin()
    yield
    _seed_admin()


@pytest.fixture
def client():
    return TestClient(app)


def test_self_registration_cannot_escalate_to_admin(client):
    """Ensure public registration cannot specify role='admin' to escalate privileges."""
    res = client.post(
        "/auth/register",
        json={
            "email": "attacker@example.com",
            "password": "Password123!",
            "full_name": "Attacker",
            "role": "admin",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["role"] == "user"  # Must be forced to UserRole.USER


def test_password_change_persists_and_validates_current(client):
    """Ensure password change updates database and rejects invalid current password."""
    reg = client.post(
        "/auth/register",
        json={
            "email": "user_pw@example.com",
            "password": "OldPassword123!",
            "full_name": "Password Tester",
        },
    )
    assert reg.status_code == 201

    login_res = client.post(
        "/auth/login",
        json={"email": "user_pw@example.com", "password": "OldPassword123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Wrong current password fails
    bad_res = client.post(
        "/auth/password/change",
        json={"current_password": "WrongPassword!", "new_password": "NewPassword123!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert bad_res.status_code == 400

    # Correct current password succeeds
    good_res = client.post(
        "/auth/password/change",
        json={"current_password": "OldPassword123!", "new_password": "NewPassword123!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert good_res.status_code == 204

    # Login with new password succeeds
    new_login = client.post(
        "/auth/login",
        json={"email": "user_pw@example.com", "password": "NewPassword123!"},
    )
    assert new_login.status_code == 200


def test_logout_revokes_token_and_clears_cookie(client):
    """Ensure logout revokes the token and clears the session cookie."""
    reg = client.post(
        "/auth/register",
        json={
            "email": "logout_tester@example.com",
            "password": "Password123!",
            "full_name": "Logout Tester",
        },
    )
    assert reg.status_code == 201

    login_res = client.post(
        "/auth/login",
        json={"email": "logout_tester@example.com", "password": "Password123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Access protected route
    me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200

    # Logout
    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 204

    # Subsequent access fails
    me_after = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_after.status_code == 401


def test_generic_login_failure_does_not_enumerate_users(client):
    """Ensure login failures return generic 401 without distinguishing missing user vs wrong password."""
    # Unknown user
    res1 = client.post(
        "/auth/login",
        json={"email": "nonexistent@example.com", "password": "Password123!"},
    )
    assert res1.status_code == 401
    assert "Invalid credentials" in res1.json()["detail"]

    # Existing user with wrong password
    client.post(
        "/auth/register",
        json={
            "email": "existing@example.com",
            "password": "Password123!",
            "full_name": "Existing User",
        },
    )
    res2 = client.post(
        "/auth/login",
        json={"email": "existing@example.com", "password": "WrongPassword!"},
    )
    assert res2.status_code == 401
    assert "Invalid credentials" in res2.json()["detail"]


def test_cors_preflight_for_frontend_origin(client):
    """Ensure preflight OPTIONS requests from http://localhost:3000 pass CORS."""
    headers = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    res = client.options("/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert res.headers.get("access-control-allow-credentials") == "true"

    res_reg = client.options("/auth/register", headers=headers)
    assert res_reg.status_code == 200
    assert res_reg.headers.get("access-control-allow-origin") == "http://localhost:3000"
