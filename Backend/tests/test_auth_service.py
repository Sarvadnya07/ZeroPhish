"""
Tests for auth/service.py â€” covers register, login, logout, MFA, OAuth guard,
token revocation, and admin seeding behaviour.
"""

import builtins
import os

import pytest

from auth.models import MFAVerify, UserCreate, UserLogin, UserRole
from auth.service import AuthService, _tokens, _users_by_email, _users_by_id

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _make_user(suffix: str = "a") -> tuple:
    email = f"test_{suffix}@example.com"
    data = UserCreate(email=email, password="Test@1234!", full_name="Test User")
    user = AuthService.register(data)
    return user, email


# â”€â”€ Registration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_register_creates_user():
    user, email = _make_user("reg1")
    assert user.email == email
    assert user.role == UserRole.USER


def test_register_duplicate_email_raises():
    _make_user("reg2")
    with pytest.raises(ValueError, match="already registered"):
        _make_user("reg2")


# â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


# â”€â”€ Token validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_validate_token_returns_user():
    _, email = _make_user("tok1")
    token = AuthService.login(UserLogin(email=email, password="Test@1234!"))
    user = AuthService.validate_token(token.access_token)
    assert user is not None
    assert user.email == email


def test_validate_token_invalid_returns_none():
    assert AuthService.validate_token("definitely-not-a-real-token") is None


# â”€â”€ Logout / revocation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


# â”€â”€ MFA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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
    # No setup_mfa called â€” no secret yet
    assert AuthService.verify_mfa(user.id, "123456") is False


def test_mfa_verify_valid_code():
    import pyotp

    user, _ = _make_user("mfa_valid")
    setup = AuthService.setup_mfa(user.id)
    code = pyotp.TOTP(setup.secret).now()
    assert AuthService.verify_mfa(user.id, code) is True


def test_mfa_verify_invalid_code():
    user, _ = _make_user("mfa_invalid")
    AuthService.setup_mfa(user.id)
    assert AuthService.verify_mfa(user.id, "999999") is False


def test_mfa_verify_missing_pyotp(monkeypatch):
    user, _ = _make_user("mfa_missing_pyotp")
    AuthService.setup_mfa(user.id)

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "pyotp":
            raise ImportError("Mocked ImportError for pyotp")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", mock_import)
    with pytest.raises(RuntimeError, match="pyotp is not installed"):
        AuthService.verify_mfa(user.id, "123456")


def test_mfa_verify_mfa_not_enabled():
    user, _ = _make_user("mfa_not_enabled")
    assert AuthService.verify_mfa(user.id, "123456") is False


# â”€â”€ OAuth production guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


# â”€â”€ Admin seeding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def test_admin_user_exists():
    from auth.service import _seed_admin

    _seed_admin()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    assert admin_email in _users_by_email


def test_admin_login_works(monkeypatch):
    test_admin_password = "TestOnly-ZeroPhish-Admin-2026!"
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("ADMIN_PASSWORD", test_admin_password)

    from auth.service import _seed_admin, _users_by_email, _users_by_id

    _users_by_email.clear()
    _users_by_id.clear()

    _seed_admin()

    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    token = AuthService.login(
        UserLogin(
            email=admin_email,
            password=test_admin_password,
        )
    )
    assert token.access_token
    user = AuthService.validate_token(token.access_token)
    assert user.role == UserRole.ADMIN


def test_admin_password_production_guard(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("ADMIN_PASSWORD", "ZeroPhish@Admin1")
    from auth.service import _seed_admin, _users_by_email, _users_by_id

    _users_by_email.clear()
    _users_by_id.clear()
    with pytest.raises(
        RuntimeError, match="ADMIN_PASSWORD must be set to a non-default value in production"
    ):
        _seed_admin()
