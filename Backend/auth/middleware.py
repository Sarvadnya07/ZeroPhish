from __future__ import annotations

import os
import urllib.parse
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import User, UserInDB, UserRole
from .service import AuthService

_bearer = HTTPBearer(auto_error=False)


def _get_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> tuple[Optional[str], bool]:
    """
    Extract auth token from either:
    1. Authorization Bearer header (used by Extension / programmatic API clients)
    2. zp_session HttpOnly cookie (used by Web browser clients)

    Returns tuple (token_string, is_cookie_auth).
    """
    if credentials and credentials.credentials:
        return credentials.credentials, False

    cookie_token = request.cookies.get("zp_session")
    if cookie_token:
        return cookie_token, True

    return None, False


def require_auth(
    request: Request,
    auth_info: tuple[Optional[str], bool] = Depends(_get_token),
) -> User:
    """Dependency: validates bearer token or session cookie, returns the authenticated User."""
    token, is_cookie = auth_info
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # If authenticated via cookie on state-changing methods, check Origin/Referer (CSRF mitigation)
    if is_cookie and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        
        # Check against allowed origins or request host
        allowed = os.getenv("ALLOWED_ORIGINS", "").split(",")
        allowed = [o.strip() for o in allowed if o.strip()]
        host = request.headers.get("host")

        if origin:
            parsed_origin = urllib.parse.urlparse(origin).netloc
            if origin not in allowed and parsed_origin != host and "localhost" not in parsed_origin and "127.0.0.1" not in parsed_origin:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF origin check failed")
        elif referer:
            parsed_ref = urllib.parse.urlparse(referer).netloc
            if parsed_ref != host and "localhost" not in parsed_ref and "127.0.0.1" not in parsed_ref:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF referer check failed")

    user_db = AuthService.validate_token(token)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid",
        )

    return User(**user_db.model_dump(exclude={"password_hash", "mfa_secret"}))


def require_role(*roles: UserRole):
    """Dependency factory: restricts endpoint to specific roles."""
    def _check(current_user: User = Depends(require_auth)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return current_user
    return _check


# Convenience aliases
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)

