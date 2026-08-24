"""
FastAPI router for user identity and admin role management.
Clerk owns user authentication and credential lifecycle.
ZeroPhish provides application user profile and administrative role assignment.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .middleware import require_admin, require_auth
from .models import User, UserRole, UserUpdate
from .service import AuthService

router = APIRouter(tags=["Authentication & Users"])


# ── Current User Profile ───────────────────────────────────────────────────────


@router.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(require_auth)):
    """Return the authenticated user profile."""
    return current_user


@router.patch("/auth/me", response_model=User)
def update_me(
    update: UserUpdate,
    current_user: User = Depends(require_auth),
):
    """Update profile fields for the authenticated user (excludes role modifications)."""
    safe_update = UserUpdate(full_name=update.full_name)
    user = AuthService.update_user(current_user.id, safe_update)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ── Admin User Management ─────────────────────────────────────────────────────


@router.get("/admin/users", response_model=List[User])
def list_users(
    role: Optional[UserRole] = None,
    current_user: User = Depends(require_admin),
):
    """List all application users (Admin only)."""
    return AuthService.list_users(role=role)


@router.get("/admin/users/{user_id}", response_model=User)
def get_user(
    user_id: str,
    current_user: User = Depends(require_admin),
):
    """Get a specific application user by ID (Admin only)."""
    user = AuthService.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/admin/users/{user_id}", response_model=User)
def admin_update_user(
    user_id: str,
    update: UserUpdate,
    current_user: User = Depends(require_admin),
):
    """Update an application user's role or status (Admin only)."""
    user = AuthService.update_user(user_id, update)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_user(
    user_id: str,
    current_user: User = Depends(require_admin),
):
    """Delete an application user record (Admin only)."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
    ok = AuthService.delete_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
