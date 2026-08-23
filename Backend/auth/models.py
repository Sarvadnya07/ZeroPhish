"""
Auth data models — User, roles, tokens, JWT.
In production replace the in-memory store with a real DB (SQLAlchemy / SQLModel).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    READONLY = "readonly"


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=128)
    role: UserRole = UserRole.USER


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None


class User(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    status: UserStatus = UserStatus.ACTIVE
    created_at: str
    last_login: Optional[str] = None
    mfa_enabled: bool = False
    scan_count: int = 0
    risk_score: float = 0.0


class UserInDB(User):
    """Internal user record — includes hashed password, never sent to client."""

    password_hash: str
    mfa_secret: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user_id: str
    role: UserRole


class MFASetup(BaseModel):
    """Return QR code seed for TOTP app setup."""

    secret: str
    otpauth_url: str


class MFAVerify(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class OAuthCallback(BaseModel):
    provider: str  # "google" | "microsoft"
    code: str
    state: str


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with a random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _, salt, dk_hex = password_hash.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def generate_token() -> str:
    return secrets.token_urlsafe(48)
