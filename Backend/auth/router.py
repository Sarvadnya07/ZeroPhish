"""
FastAPI router for user identity and admin role management.

Clerk owns user authentication and credential lifecycle.
ZeroPhish provides application user profile and administrative role assignment.

This router exposes endpoints for:
- Current user profile (read/update)
- Admin user management (list, get, update, delete)
- All endpoints are protected by RBAC (require_auth, require_admin)
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status
from pydantic import UUID4

from security.audit_logger import AuditLogger

from .middleware import require_admin, require_auth
from .models import User, UserRole, UserUpdate
from .service import AuthService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Authentication & Users"])


# ---------- Current User Profile ----------
@router.get(
    "/auth/me",
    response_model=User,
    summary="Get current user profile",
    description="Returns the authenticated user's application profile.",
)
async def get_me(current_user: User = Depends(require_auth)) -> User:
    """Return the authenticated user profile."""
    return current_user


@router.patch(
    "/auth/me",
    response_model=User,
    summary="Update current user profile",
    description="Update the authenticated user's profile (only full_name can be changed).",
)
async def update_me(
    update: UserUpdate,
    current_user: User = Depends(require_auth),
) -> User:
    """
    Update profile fields for the authenticated user.

    Role and status updates are not allowed on this endpoint; they require admin privileges.
    """
    # Only allow updating full_name; preserve the current role/status values.
    safe_update = UserUpdate(
        full_name=update.full_name,
        role=current_user.role,
        status=current_user.status,
    )
    user = await AuthService.update_user(current_user.id, safe_update)
    if not user:
        # This should not happen since the user exists, but safeguard
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


# ---------- Admin User Management ----------
@router.get(
    "/admin/users",
    response_model=List[User],
    summary="List all users",
    description="Returns a list of all application users. Admin only.",
)
async def list_users(
    role: Optional[UserRole] = None,
    current_user: User = Depends(require_admin),
) -> List[User]:
    """List all application users, optionally filtered by role (Admin only)."""
    return await AuthService.list_users(role=role)


@router.get(
    "/admin/users/{user_id}",
    response_model=User,
    summary="Get a user by ID",
    description="Returns a specific user's profile. Admin only.",
)
async def get_user(
    user_id: str = Path(..., min_length=1, description="Internal user ID"),
    current_user: User = Depends(require_admin),
) -> User:
    """Get a specific application user by ID (Admin only)."""
    user = await AuthService.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.patch(
    "/admin/users/{user_id}",
    response_model=User,
    summary="Update a user",
    description="Update a user's role or status. Admin only.",
)
async def admin_update_user(
    user_id: str = Path(..., min_length=1),
    update: UserUpdate = Body(...),
    current_user: User = Depends(require_admin),
) -> User:
    """
    Update an application user's role or status (Admin only).

    Admin can update any field except id and clerk_user_id.
    """
    # Prevent self-downgrade of admin privileges? Let the service handle it.
    user = await AuthService.update_user(user_id, update)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.delete(
    "/admin/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user",
    description="Deletes a user account. Admin cannot delete their own account.",
)
async def admin_delete_user(
    user_id: str = Path(..., min_length=1),
    current_user: User = Depends(require_admin),
) -> None:
    """Delete an application user record (Admin only)."""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own admin account",
        )
    ok = await AuthService.delete_user(user_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )