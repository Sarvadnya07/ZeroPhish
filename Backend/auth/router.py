"""
Auth router — /auth/* endpoints:
  POST /auth/register
  POST /auth/login
  POST /auth/logout
  GET  /auth/me
  PATCH /auth/me
  POST /auth/mfa/setup
  POST /auth/mfa/verify
  POST /auth/oauth/{provider}/callback
  GET  /admin/users         (admin only)
  PATCH /admin/users/{id}  (admin only)
  DELETE /admin/users/{id} (admin only)
"""
from __future__ import annotations

import os
from typing import Optional, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Path

from .middleware import _get_token, require_auth, require_admin
from .models import (
    MFAVerify,
    OAuthCallback,
    PasswordChangeRequest,
    Token,
    User,
    UserCreate,
    UserLogin,
    UserRole,
    UserUpdate,
    verify_password,
)
from .service import AuthService, _users_by_id
from security.dependencies import limiter

router = APIRouter(tags=["auth"])


# ── Public ────────────────────────────────────────────────────────────────────

@router.post("/auth/register", response_model=User, status_code=201)
@limiter.limit("3/minute")
def register(request: Request, data: UserCreate):
    try:
        return AuthService.register(data)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, data: UserLogin, response: Response):
    try:
        token = AuthService.login(data)
        is_prod = os.getenv("ENV", "development") == "production"
        response.set_cookie(
            key="zp_session",
            value=token.access_token,
            httponly=True,
            samesite="lax",
            secure=is_prod,
            max_age=token.expires_in,
            path="/",
        )
        return token
    except PermissionError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/auth/logout", status_code=204)
def logout(
    response: Response,
    auth_info: tuple[Optional[str], bool] = Depends(_get_token),
    current_user: User = Depends(require_auth),
):
    token, _ = auth_info
    if token:
        AuthService.logout(token)
    is_prod = os.getenv("ENV", "development") == "production"
    response.delete_cookie(
        key="zp_session",
        path="/",
        httponly=True,
        samesite="lax",
        secure=is_prod,
    )
    return None



# ── Authenticated user self-service ──────────────────────────────────────────

@router.get("/auth/me", response_model=User)
def me(current_user: User = Depends(require_auth)):
    return current_user


@router.patch("/auth/me", response_model=User)
def update_me(update: UserUpdate, current_user: User = Depends(require_auth)):
    # Users can only update their own name (not role/status — admin only)
    safe_update = UserUpdate(full_name=update.full_name)
    return AuthService.update_user(current_user.id, safe_update)


@router.post("/auth/password/change", status_code=204)
def change_password(req: PasswordChangeRequest, current_user: User = Depends(require_auth)):
    user_db = _users_by_id.get(current_user.id)
    if not user_db or not verify_password(req.current_password, user_db.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    from .models import hash_password
    user_db.password_hash = hash_password(req.new_password)


# ── MFA ───────────────────────────────────────────────────────────────────────

@router.post("/auth/mfa/setup")
def mfa_setup(current_user: User = Depends(require_auth)):
    return AuthService.setup_mfa(current_user.id)


@router.post("/auth/mfa/verify")
def mfa_verify(body: MFAVerify, current_user: User = Depends(require_auth)):
    ok = AuthService.verify_mfa(current_user.id, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired MFA code")
    return {"mfa_enabled": True}


# ── OAuth ─────────────────────────────────────────────────────────────────────

@router.post("/auth/oauth/callback", response_model=Token)
def oauth_callback(body: OAuthCallback):
    try:
        return AuthService.oauth_callback(body.provider, body.code)
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))


# ── Admin user management ─────────────────────────────────────────────────────

@router.get("/admin/users", response_model=list[User])
def list_users(role: Optional[str] = None, _: User = Depends(require_admin)):
    r = UserRole(role) if role else None
    return AuthService.list_users(role=r)


@router.get("/admin/users/{user_id}", response_model=User)
def get_user(user_id: str, _: User = Depends(require_admin)):
    u = AuthService.get_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u


@router.patch("/admin/users/{user_id}", response_model=User)
def update_user(user_id: str, update: UserUpdate, _: User = Depends(require_admin)):
    try:
        return AuthService.update_user(user_id, update)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/admin/users/{user_id}", status_code=204)
def delete_user(user_id: str, _: User = Depends(require_admin)):
    AuthService.delete_user(user_id)
