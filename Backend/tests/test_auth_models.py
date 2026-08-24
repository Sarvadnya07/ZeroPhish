"""
Tests for auth/models.py — validates Clerk User models, serialization, and role enums.
"""

import pytest
from auth.models import User, UserInDB, UserRole, UserStatus, UserUpdate


def test_user_model_instantiation():
    user = User(
        id="zp_user_123",
        clerk_user_id="user_clerk_123",
        email="test@example.com",
        full_name="Test User",
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
        created_at="2026-08-24T12:00:00Z",
    )
    assert user.id == "zp_user_123"
    assert user.clerk_user_id == "user_clerk_123"
    assert user.role == UserRole.USER
    assert user.status == UserStatus.ACTIVE


def test_user_update_model():
    update = UserUpdate(full_name="New Name", role=UserRole.ANALYST)
    data = update.model_dump(exclude_unset=True)
    assert data["full_name"] == "New Name"
    assert data["role"] == UserRole.ANALYST
    assert "status" not in data


def test_user_role_enum_values():
    assert UserRole.ADMIN.value == "admin"
    assert UserRole.ANALYST.value == "analyst"
    assert UserRole.USER.value == "user"
    assert UserRole.READONLY.value == "readonly"
