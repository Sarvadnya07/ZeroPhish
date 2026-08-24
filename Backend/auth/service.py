"""
Auth Service — Repositories-backed user and authentication management.
Handles registration, login, token lifecycle, MFA, and OAuth.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
import uuid
from typing import Dict, List, Optional

from repositories.factory import get_user_repository

from .models import (
    MFASetup,
    Token,
    User,
    UserCreate,
    UserInDB,
    UserLogin,
    UserRole,
    UserStatus,
    UserUpdate,
    generate_token,
    hash_password,
    verify_password,
)

TOKEN_TTL = int(os.getenv("AUTH_TOKEN_TTL", "86400"))  # 24 h default

# Direct state references for backwards-compatible test access
_users_by_id: Dict[str, UserInDB] = {}
_users_by_email: Dict[str, str] = {}
_tokens: Dict[str, dict] = {}


def _is_weak_password(p: str) -> bool:
    return p in {"ZeroPhish@Admin1", "admin", "password", "123456", "changeme"}


def _seed_admin() -> None:
    """Seed a default admin account if none exist."""
    if _users_by_email:
        return
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    admin_pass = os.getenv("ADMIN_PASSWORD", "ZeroPhish@Admin1")
    if _is_weak_password(admin_pass):
        if os.getenv("ENV", "development") == "production":
            logging.critical("ADMIN_PASSWORD must be set to a non-default value in production")
            raise RuntimeError("ADMIN_PASSWORD must be set to a non-default value in production")
        else:
            logging.warning("Using default or weak admin password in development/test environment.")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    admin_user = UserInDB(
        id=str(uuid.uuid4()),
        email=admin_email,
        full_name="System Administrator",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        created_at=now,
        password_hash=hash_password(admin_pass),
    )
    repo = get_user_repository()
    repo.save(admin_user)
    _users_by_id[admin_user.id] = admin_user
    _users_by_email[admin_user.email] = admin_user.id


# Seed admin on module import
_seed_admin()


class AuthService:
    # ── User management ───────────────────────────────────────────────────────

    @staticmethod
    def register(data: UserCreate) -> User:
        repo = get_user_repository()
        if repo.get_by_email(data.email):
            raise ValueError("Email already registered")

        uid = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Always enforce USER role for public self-registration (prevent role escalation)
        enforced_role = UserRole.USER

        user_in_db = UserInDB(
            id=uid,
            email=data.email,
            full_name=data.full_name,
            role=enforced_role,
            status=UserStatus.ACTIVE,
            created_at=now,
            password_hash=hash_password(data.password),
        )
        saved = repo.save(user_in_db)
        _users_by_id[saved.id] = saved
        _users_by_email[saved.email] = saved.id
        from security.audit_logger import log_register

        log_register(user_id=saved.id, role=saved.role.value)
        return User(**saved.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def login(data: UserLogin) -> Token:
        from security.audit_logger import log_login_failure, log_login_success

        repo = get_user_repository()
        user = repo.get_by_email(data.email)
        domain = data.email.split("@")[-1] if "@" in data.email else "[unknown]"
        if not user:
            log_login_failure(reason="user_not_found", email_domain=domain)
            raise PermissionError("Invalid credentials")
        if user.status != UserStatus.ACTIVE:
            log_login_failure(reason="account_suspended", user_id=user.id)
            raise PermissionError("Account suspended")
        if not verify_password(data.password, user.password_hash):
            log_login_failure(reason="invalid_password", user_id=user.id)
            raise PermissionError("Invalid credentials")

        user.last_login = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        repo.save(user)
        token = AuthService._issue_token(user)
        log_login_success(user_id=user.id, role=user.role.value)
        return token

    @staticmethod
    def _issue_token(user: UserInDB) -> Token:
        repo = get_user_repository()
        token_str = generate_token()
        expires_at = time.time() + TOKEN_TTL
        repo.store_token(token_str, user.id, expires_at)
        _tokens[token_str] = {"user_id": user.id, "expires_at": expires_at}
        return Token(
            access_token=token_str,
            expires_in=TOKEN_TTL,
            user_id=user.id,
            role=user.role,
        )

    @staticmethod
    def validate_token(token: str) -> Optional[UserInDB]:
        repo = get_user_repository()
        return repo.validate_token(token)

    @staticmethod
    def logout(token: str) -> None:
        repo = get_user_repository()
        user_db = repo.validate_token(token)
        if user_db:
            from security.audit_logger import log_logout

            log_logout(user_id=user_db.id)
        repo.revoke_token(token)
        _tokens.pop(token, None)

    @staticmethod
    def change_password(user_id: str, current_password: str, new_password: str) -> None:
        repo = get_user_repository()
        user = repo.get_by_id(user_id)
        if not user or not verify_password(current_password, user.password_hash):
            raise ValueError("Current password incorrect")
        if len(new_password) < 8 or len(new_password) > 128:
            raise ValueError("Password must be between 8 and 128 characters")

        user.password_hash = hash_password(new_password)
        repo.save(user)
        _users_by_id[user.id] = user

    @staticmethod
    def get_user(user_id: str) -> Optional[User]:
        repo = get_user_repository()
        u = repo.get_by_id(user_id)
        if not u:
            return None
        return User(**u.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def list_users(role: Optional[UserRole] = None) -> List[User]:
        repo = get_user_repository()
        users = repo.list_all(role=role)
        return [User(**u.model_dump(exclude={"password_hash", "mfa_secret"})) for u in users]

    @staticmethod
    def update_user(user_id: str, update: UserUpdate) -> User:
        repo = get_user_repository()
        user = repo.update(user_id, update)
        if not user:
            raise ValueError("User not found")
        _users_by_id[user.id] = user
        return User(**user.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def delete_user(user_id: str) -> None:
        repo = get_user_repository()
        u = repo.get_by_id(user_id)
        if u:
            _users_by_email.pop(u.email, None)
            _users_by_id.pop(user_id, None)
        repo.delete(user_id)

    @staticmethod
    def increment_scan(user_id: str, final_score: float) -> None:
        repo = get_user_repository()
        repo.increment_scan(user_id, final_score)

    # ── MFA (TOTP) ────────────────────────────────────────────────────────────

    @staticmethod
    def setup_mfa(user_id: str) -> MFASetup:
        repo = get_user_repository()
        user = repo.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        user.mfa_secret = secret
        repo.save(user)
        otpauth = f"otpauth://totp/ZeroPhish:{user.email}?secret={secret}&issuer=ZeroPhish"
        return MFASetup(secret=secret, otpauth_url=otpauth)

    @staticmethod
    def verify_mfa(user_id: str, code: str) -> bool:
        from security.audit_logger import log_mfa_failure, log_mfa_success

        repo = get_user_repository()
        user = repo.get_by_id(user_id)
        if not user or not user.mfa_secret:
            log_mfa_failure(user_id=user_id, reason="no_mfa_secret")
            return False
        try:
            import pyotp  # type: ignore

            totp = pyotp.TOTP(user.mfa_secret)
            valid = totp.verify(code)
        except ImportError:
            logging.critical("MFA verification failed: pyotp is not installed.")
            raise RuntimeError("MFA verification failed: pyotp is not installed.")
        if valid:
            user.mfa_enabled = True
            repo.save(user)
            log_mfa_success(user_id=user_id)
        else:
            log_mfa_failure(user_id=user_id, reason="invalid_code")
        return valid

    # ── OAuth ─────────────────────────────────────────────────────────────────

    @classmethod
    def oauth_callback(cls, provider: str, code: str) -> Token:
        if provider not in ("google", "microsoft"):
            raise NotImplementedError(f"OAuth provider '{provider}' is not supported")

        if (
            os.getenv("ENV", "development") == "production"
            or os.getenv("ENABLE_MOCK_OAUTH", "false").lower() != "true"
        ):
            raise NotImplementedError(
                "OAuth provider integration requires production API credentials"
            )

        repo = get_user_repository()
        mock_email = f"oauth_user+{code[:6]}@{provider}.com"
        existing = repo.get_by_email(mock_email)
        if existing:
            return cls._issue_token(existing)

        new_user = UserInDB(
            id=str(uuid.uuid4()),
            email=mock_email,
            full_name=f"{provider.capitalize()} User",
            password_hash=hash_password(str(uuid.uuid4())),
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            mfa_secret=None,
        )
        saved = repo.save(new_user)
        _users_by_id[saved.id] = saved
        _users_by_email[saved.email] = saved.id
        return cls._issue_token(saved)
