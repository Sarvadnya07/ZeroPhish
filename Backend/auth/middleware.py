"""
ZeroPhish Authorization & Security Middleware.
Authenticates Clerk session tokens and enforces server-side Role-Based Access Control (RBAC).
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from security.audit_logger import AuditLogger

from .clerk import ClerkTokenVerifier, ClerkVerificationError
from .models import User, UserRole
from .service import AuthService

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)


def _get_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> tuple[Optional[str], bool]:
    """Extract auth token from Bearer header or session cookie."""
    if credentials and credentials.credentials:
        return credentials.credentials, False

    cookie_token = request.cookies.get("__session") or request.cookies.get("zp_session")
    if cookie_token:
        return cookie_token, True

    return None, False


def require_auth(
    request: Request,
    auth_info: tuple[Optional[str], bool] = Depends(_get_token),
) -> User:
    """Dependency: authenticates Clerk token and returns application User."""
    token, is_cookie = auth_info
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # CSRF mitigation for cookie-based state mutations
    if is_cookie and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        allowed = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
        host = request.headers.get("host")

        if origin:
            parsed_origin = urllib.parse.urlparse(origin).netloc
            if (
                origin not in allowed
                and parsed_origin != host
                and "localhost" not in parsed_origin
                and "127.0.0.1" not in parsed_origin
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="CSRF origin check failed"
                )
        elif referer:
            parsed_ref = urllib.parse.urlparse(referer).netloc
            if (
                parsed_ref != host
                and "localhost" not in parsed_ref
                and "127.0.0.1" not in parsed_ref
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="CSRF referer check failed"
                )

    try:
        payload = ClerkTokenVerifier.verify_token(token)
    except ClerkVerificationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )

    clerk_user_id = payload["sub"]
    email = payload["email"]
    full_name = payload["full_name"]

    user = AuthService.get_or_create_user(
        clerk_user_id=clerk_user_id,
        email=email,
        full_name=full_name,
    )

    if user.status.value == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )

    return user


def require_role(*roles: UserRole):
    """Dependency factory: restricts endpoint to specific application roles."""

    def _check(current_user: User = Depends(require_auth)) -> User:
        if current_user.role not in roles:
            AuditLogger.log_event(
                event_type="AUTHZ_DENIED",
                user_id=current_user.id,
                details={
                    "user_role": current_user.role.value,
                    "required_roles": [r.value for r in roles],
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return current_user

    return _check


# Convenience aliases
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
