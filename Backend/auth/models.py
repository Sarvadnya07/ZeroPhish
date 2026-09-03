"""
Auth data models for Clerk-integrated ZeroPhish identity & authorization.

Clerk owns authentication, sessions, and credential verification.
ZeroPhish maintains application user mapping and RBAC roles.

This module defines the core user entity, role-based access control (RBAC)
enums, and request/response schemas for user management operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------- Enums ----------
class UserRole(str, Enum):
    """Application-level roles for RBAC enforcement."""

    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    READONLY = "readonly"


class UserStatus(str, Enum):
    """Account status representing user availability."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"


# ---------- Request/Response Models ----------
class UserUpdate(BaseModel):
    """
    Schema for updating a user's profile or role.

    All fields are optional; only provided fields will be updated.
    """

    full_name: Optional[str] = Field(None, min_length=1, max_length=100, description="User's full name")
    role: Optional[UserRole] = Field(None, description="Assigned role for RBAC")
    status: Optional[UserStatus] = Field(None, description="Account status")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            cleaned = v.strip()
            if not cleaned:
                raise ValueError("full_name cannot be empty or whitespace only")
            return cleaned
        return v


class User(BaseModel):
    """
    Application user entity.

    This is the primary user model used throughout the application.
    It links the Clerk authentication identity with application-specific
    data (role, status, risk score, etc.).
    """

    id: str = Field(..., min_length=1, description="Internal user ID (UUID)")
    clerk_user_id: str = Field(..., min_length=1, description="Clerk user ID from the identity provider")
    email: str = Field(..., min_length=3, description="Primary email address")
    full_name: str = Field(..., min_length=1, max_length=100, description="User's display name")
    role: UserRole = Field(default=UserRole.USER, description="RBAC role")
    status: UserStatus = Field(default=UserStatus.ACTIVE, description="Account status")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last successful login timestamp")
    scan_count: int = Field(default=0, ge=0, description="Total number of scans performed by this user")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Aggregated threat risk score for the user")

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("full_name cannot be empty or whitespace only")
        return cleaned

    @field_validator("clerk_user_id", "id")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field cannot be empty")
        return v


# ---------- Repository Entity ----------
class UserInDB(User):
    """
    Repository user entity — maps internal ID to Clerk user ID and RBAC profile.

    This is a type alias for the User model when stored in the database.
    It ensures consistency between the application layer and persistence layer.
    """

    # Inherits all fields from User; used to distinguish from API response models
    pass


# ---------- Additional helper: Clerk user creation payload ----------
class ClerkUserCreate(BaseModel):
    """
    Minimal payload for creating a user from Clerk authentication data.
    Typically used when a user first logs in via Clerk.
    """

    clerk_user_id: str = Field(..., min_length=1)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("full_name cannot be empty or whitespace only")
        return cleaned