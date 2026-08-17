"""
Tests for auth/service.py — covers register, login, logout, MFA, OAuth guard,
token revocation, and admin seeding behaviour.
"""
import os
import pytest
from auth.service import AuthService, _tokens, _users_by_email, _users_by_id
from auth.models import UserCreate, UserLogin, UserRole, MFAVerify


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_user(suffix: str = "a") -> tuple:
    email = f"test_{suffix}@example.com"
    data = UserCreate(email=email, password="Test@1234!", full_name="Test User")
    user = AuthService.register(data)
    return user, email


# ── Registration ─────────────────────────────────────────────────────────────

def test_register_creates_user():
    user, email = _make_user("reg1")
    assert user.email == email
    assert user.role == UserRole.USER


def test_register_duplicate_email_raises():
    _make_user("reg2")
    with pytest.raises(ValueError, match="already registered"):
        _make_user("reg2")


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_returns_token():
    _, email = _make_user("login1")
    token = AuthService.login(UserLogin(email=email, password="Test@1234!"))
    assert token.access_token
    assert token.expires_in == int(os.getenv("AUTH_TOKEN_TTL", "86400"))


def test_login_wrong_password_raises():
    _, email = _make_user("login2")
    with pytest.raises(PermissionError):
        AuthService.login(UserLogin(email=email, password="wrong"))


def test_login_unknown_email_raises():
    with pytest.raises(PermissionError):
        AuthService.login(UserLogin(email="nobody@example.com", password="x"))



# ── Token validation ──────────────────────────────────────────────────────────

def test_validate_token_returns_user():
    _, email = _make_user("tok1")
    token = AuthService.login(UserLogin(email=email, password="Test@1234!"))
    user = AuthService.validate_token(token.access_token)
    assert user is not None
    assert user.email == email


def test_validate_token_invalid_returns_none():
    assert AuthService.validate_token("definitely-not-a-real-token") is None


# ── Logout / revocation ───────────────────────────────────────────────────────

def test_logout_revokes_token():
    _, email = _make_user("logout1")
    token = AuthService.login(UserLogin(email=email, password="Test@1234!"))
    raw = token.access_token
    assert AuthService.validate_token(raw) is not None
    AuthService.logout(raw)
    assert AuthService.validate_token(raw) is None


def test_logout_twice_is_safe():
    _, email = _make_user("logout2")
    token = AuthService.login(UserLogin(email=email, password="Test@1234!"))
    AuthService.logout(token.access_token)
    AuthService.logout(token.access_token)  # should not raise


# ── MFA ───────────────────────────────────────────────────────────────────────

def test_mfa_setup_returns_secret():
    user, _ = _make_user("mfa1")
    setup = AuthService.setup_mfa(user.id)
    assert setup.secret
    assert "otpauth://totp" in setup.otpauth_url


def test_mfa_verify_wrong_code_returns_false():
    user, _ = _make_user("mfa2")
    AuthService.setup_mfa(user.id)
    assert AuthService.verify_mfa(user.id, "000000") is False


def test_mfa_verify_no_secret_returns_false():
    user, _ = _make_user("mfa3")
    # No setup_mfa called — no secret yet
    assert AuthService.verify_mfa(user.id, "123456") is False


# ── OAuth production guard ────────────────────────────────────────────────────

def test_oauth_callback_raises_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(NotImplementedError):
        AuthService.oauth_callback("google", "any-code")


def test_oauth_callback_raises_without_flag(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("ENABLE_MOCK_OAUTH", "false")
    with pytest.raises(NotImplementedError):
        AuthService.oauth_callback("google", "any-code")


def test_oauth_mock_works_in_dev(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("ENABLE_MOCK_OAUTH", "true")
    token = AuthService.oauth_callback("google", "testcode123")
    assert token.access_token


# ── Admin seeding ─────────────────────────────────────────────────────────────

def test_admin_user_exists():
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    assert admin_email in _users_by_email


def test_admin_login_works():
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    token = AuthService.login(UserLogin(email=admin_email, password="ZeroPhish@Admin1"))
    assert token.access_token
    user = AuthService.validate_token(token.access_token)
    assert user.role == UserRole.ADMIN
