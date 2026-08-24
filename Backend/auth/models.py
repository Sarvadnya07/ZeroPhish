"""
Auth data models for Clerk-integrated ZeroPhish identity & authorization.
Clerk owns authentication, sessions, and credential verification.
ZeroPhish maintains application user mapping and RBAC roles.
"""

from __future__ import annotations

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


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None


class User(BaseModel):
    id: str
    clerk_user_id: str
    email: str
    full_name: str
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    created_at: str
    last_login: Optional[str] = None
    scan_count: int = 0
    risk_score: float = 0.0


class UserInDB(User):
    """Repository user entity — maps internal ID to Clerk user ID and RBAC profile."""

    pass
