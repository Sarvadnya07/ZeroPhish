"""
Tests for auth/service.py — covers Clerk identity mapping, user provisioning,
profile retrieval, role assignment, and user administration.
"""

import os
import pytest

from auth.models import UserRole, UserStatus, UserUpdate
from auth.service import AuthService, _users_by_clerk_id, _users_by_email, _users_by_id


@pytest.fixture(autouse=True)
def reset_service_state():
    _users_by_id.clear()
    _users_by_email.clear()
    _users_by_clerk_id.clear()
    yield


def test_get_or_create_user_provisions_new_user():
    user = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_1",
        email="alice@example.com",
        full_name="Alice Sentinel",
    )
    assert user.id is not None
    assert user.clerk_user_id == "user_clerk_1"
    assert user.email == "alice@example.com"
    assert user.full_name == "Alice Sentinel"
    assert user.role == UserRole.USER
    assert user.status == UserStatus.ACTIVE


def test_get_or_create_user_returns_existing_user():
    u1 = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_2",
        email="bob@example.com",
        full_name="Bob Security",
    )
    u2 = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_2",
        email="bob@example.com",
        full_name="Bob Security",
    )
    assert u1.id == u2.id
    assert u1.clerk_user_id == u2.clerk_user_id


def test_admin_provisioning_via_admin_email(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", "admin@zerophish.local")
    user = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_admin",
        email="admin@zerophish.local",
        full_name="Global Administrator",
    )
    assert user.role == UserRole.ADMIN


def test_user_update_and_lookup():
    user = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_3",
        email="charlie@example.com",
        full_name="Charlie Analyst",
    )
    updated = AuthService.update_user(user.id, UserUpdate(role=UserRole.ANALYST))
    assert updated is not None
    assert updated.role == UserRole.ANALYST

    found_by_id = AuthService.get_user_by_id(user.id)
    assert found_by_id is not None
    assert found_by_id.role == UserRole.ANALYST

    found_by_clerk = AuthService.get_user_by_clerk_id("user_clerk_3")
    assert found_by_clerk is not None
    assert found_by_clerk.id == user.id


def test_delete_user():
    user = AuthService.get_or_create_user(
        clerk_user_id="user_clerk_del",
        email="delete_me@example.com",
        full_name="Delete Me",
    )
    assert AuthService.get_user_by_id(user.id) is not None
    ok = AuthService.delete_user(user.id)
    assert ok is True
    assert AuthService.get_user_by_id(user.id) is None
