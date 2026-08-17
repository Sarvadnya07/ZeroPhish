"""
Auth Service — in-memory user store (swap for SQLAlchemy in production).
Handles registration, login, JWT-style token management, MFA, OAuth stubs.
"""
from __future__ import annotations

import base64
import os
import secrets
import time
import uuid
from typing import Dict, List, Optional

from .models import (
    User,
    UserCreate,
    UserInDB,
    UserLogin,
    UserRole,
    UserStatus,
    UserUpdate,
    Token,
    MFASetup,
    hash_password,
    verify_password,
    generate_token,
)

# ── In-memory stores ──────────────────────────────────────────────────────────
_users_by_id: Dict[str, UserInDB] = {}
_users_by_email: Dict[str, str] = {}          # email → id
_tokens: Dict[str, dict] = {}                  # token → {user_id, expires_at}

TOKEN_TTL = int(os.getenv("AUTH_TOKEN_TTL", "86400"))  # 24 h default


def _seed_admin() -> None:
    """Seed a default admin account if none exist."""
    if _users_by_email:
        return
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    admin_pass  = os.getenv("ADMIN_PASSWORD", "ZeroPhish@Admin1")
    _create_user_internal(
        UserCreate(
            email=admin_email,
            password=admin_pass,
            full_name="System Administrator",
            role=UserRole.ADMIN,
        )
    )


def _create_user_internal(data: UserCreate) -> UserInDB:
    uid = str(uuid.uuid4())
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    user = UserInDB(
        id=uid,
        email=data.email,
        full_name=data.full_name,
        role=data.role,
        status=UserStatus.ACTIVE,
        created_at=now,
        password_hash=hash_password(data.password),
    )
    _users_by_id[uid]          = user
    _users_by_email[data.email] = uid
    return user


# Seed on import
_seed_admin()


class AuthService:
    # ── User management ───────────────────────────────────────────────────────

    @staticmethod
    def register(data: UserCreate) -> User:
        if data.email in _users_by_email:
            raise ValueError("Email already registered")
        user = _create_user_internal(data)
        return User(**user.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def login(data: UserLogin) -> Token:
        uid = _users_by_email.get(data.email)
        if not uid:
            raise PermissionError("Invalid credentials")
        user = _users_by_id[uid]
        if user.status != UserStatus.ACTIVE:
            raise PermissionError("Account suspended")
        if not verify_password(data.password, user.password_hash):
            raise PermissionError("Invalid credentials")
        # Update last login
        user.last_login = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return AuthService._issue_token(user)

    @staticmethod
    def _issue_token(user: UserInDB) -> Token:
        token_str = generate_token()
        expires_at = time.time() + TOKEN_TTL
        _tokens[token_str] = {"user_id": user.id, "expires_at": expires_at}
        return Token(
            access_token=token_str,
            expires_in=TOKEN_TTL,
            user_id=user.id,
            role=user.role,
        )

    @staticmethod
    def validate_token(token: str) -> Optional[UserInDB]:
        record = _tokens.get(token)
        if not record:
            return None
        if time.time() > record["expires_at"]:
            _tokens.pop(token, None)
            return None
        return _users_by_id.get(record["user_id"])

    @staticmethod
    def logout(token: str) -> None:
        _tokens.pop(token, None)

    @staticmethod
    def get_user(user_id: str) -> Optional[User]:
        u = _users_by_id.get(user_id)
        if not u:
            return None
        return User(**u.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def list_users(role: Optional[UserRole] = None) -> List[User]:
        users = list(_users_by_id.values())
        if role:
            users = [u for u in users if u.role == role]
        return [User(**u.model_dump(exclude={"password_hash", "mfa_secret"})) for u in users]

    @staticmethod
    def update_user(user_id: str, update: UserUpdate) -> User:
        user = _users_by_id.get(user_id)
        if not user:
            raise ValueError("User not found")
        if update.full_name is not None:
            user.full_name = update.full_name
        if update.role is not None:
            user.role = update.role
        if update.status is not None:
            user.status = update.status
        return User(**user.model_dump(exclude={"password_hash", "mfa_secret"}))

    @staticmethod
    def delete_user(user_id: str) -> None:
        user = _users_by_id.pop(user_id, None)
        if user:
            _users_by_email.pop(user.email, None)

    @staticmethod
    def increment_scan(user_id: str, final_score: float) -> None:
        """Called after each scan to update per-user stats."""
        user = _users_by_id.get(user_id)
        if not user:
            return
        user.scan_count += 1
        # Rolling average of final scores
        n = user.scan_count
        user.risk_score = ((user.risk_score * (n - 1)) + final_score) / n

    # ── MFA (TOTP stub) ───────────────────────────────────────────────────────

    @staticmethod
    def setup_mfa(user_id: str) -> MFASetup:
        user = _users_by_id.get(user_id)
        if not user:
            raise ValueError("User not found")
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        user.mfa_secret = secret
        otpauth = f"otpauth://totp/ZeroPhish:{user.email}?secret={secret}&issuer=ZeroPhish"
        return MFASetup(secret=secret, otpauth_url=otpauth)

    @staticmethod
    def verify_mfa(user_id: str, code: str) -> bool:
        """
        Real TOTP verification requires pyotp.  This stub accepts any 6-digit code
        when MFA secret is set, and enables MFA on the account.
        Install pyotp and replace this stub for production.
        """
        user = _users_by_id.get(user_id)
        if not user or not user.mfa_secret:
            return False
        try:
            import pyotp  # type: ignore
            totp = pyotp.TOTP(user.mfa_secret)
            valid = totp.verify(code)
        except ImportError:
            valid = len(code) == 6 and code.isdigit()  # permissive stub
        if valid:
            user.mfa_enabled = True
        return valid

    # ── OAuth stub ────────────────────────────────────────────────────────────

    @classmethod
    def oauth_callback(cls, provider: str, code: str) -> Token:
        """
        Mock OAuth callback handler. In production, exchanges `code` for an
        access token via Google/Microsoft APIs and fetches user information.
        """
        if provider not in ("google", "microsoft"):
            raise NotImplementedError(f"OAuth provider '{provider}' is not supported")

        if os.getenv("ENV", "development") == "production" or os.getenv("ENABLE_MOCK_OAUTH", "false").lower() != "true":
            raise NotImplementedError("OAuth provider integration requires production API credentials")
            
        # Mock API exchange
        mock_email = f"oauth_user+{code[:6]}@{provider}.com"
        
        # Check if user already exists
        uid = _users_by_email.get(mock_email)
        if uid:
            return cls._issue_token(_users_by_id[uid])
                
        # Register the user seamlessly
        new_user = UserInDB(
            id=str(uuid.uuid4()),
            email=mock_email,
            full_name=f"{provider.capitalize()} User",
            password_hash=hash_password(str(uuid.uuid4())), # random unusable
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            mfa_secret=None
        )
        _users_by_id[new_user.id] = new_user
        _users_by_email[new_user.email] = new_user.id
        
        return cls._issue_token(new_user)
