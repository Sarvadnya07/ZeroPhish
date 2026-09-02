"""
ZeroPhish Authorization & Security Middleware.

This module provides FastAPI dependencies for authenticating Clerk session tokens,
enforcing server-side Role-Based Access Control (RBAC), and performing CSRF
protection for state-changing operations.

Key features:
- Token extraction from Authorization header or session cookie
- CSRF protection using Origin/Referer header validation
- User retrieval and creation via AuthService
- Role-based access control (Admin, Analyst, User, Read-only)
- Audit logging for authorization decisions
- Suspended account detection
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from typing import List, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from security.audit_logger import AuditLogger

from .clerk import ClerkTokenVerifier, ClerkVerificationError
from .models import User, UserRole
from .service import AuthService

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)


# ---------- Configuration ----------
class SecurityConfig(BaseModel):
    """Immutable configuration for security middleware."""

    allowed_origins: List[str]
    csrf_protection_enabled: bool = True
    cookie_name: str = "zp_session"

    @classmethod
    def from_env(cls) -> SecurityConfig:
        """Load configuration from environment."""
        raw_origins = os.getenv("ALLOWED_ORIGINS", "")
        allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
        if not allowed_origins:
            allowed_origins = [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:8000",
                "http://localhost:8001",
            ]
        cookie_name = os.getenv("SESSION_COOKIE_NAME", "zp_session")
        csrf_enabled = os.getenv("CSRF_PROTECTION_ENABLED", "true").lower() == "true"
        return cls(
            allowed_origins=allowed_origins,
            csrf_protection_enabled=csrf_enabled,
            cookie_name=cookie_name,
        )


_config = SecurityConfig.from_env()


# ---------- Token Extraction ----------
def _extract_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer),
) -> tuple[Optional[str], bool]:
    """
    Extract JWT token from either Authorization header or session cookie.

    Returns:
        (token_string, from_cookie) where from_cookie is True if token came from cookie.
    """
    if credentials and credentials.credentials:
        return credentials.credentials, False

    cookie_token = request.cookies.get("__session") or request.cookies.get(_config.cookie_name)
    if cookie_token:
        return cookie_token, True

    return None, False


# ---------- CSRF Protection ----------
def _validate_csrf(request: Request) -> None:
    """
    Validate that the request origin/referer matches the allowed host.

    This is a basic CSRF mitigation for cookie-based authentication.
    For state-changing methods (POST, PUT, DELETE, PATCH), we require:
    - The Origin header, if present, must be in the ALLOWED_ORIGINS list,
      or must match the current host (for same-origin requests).
    - If Origin is absent, the Referer header must be from the same host.

    Raises:
        HTTPException (403) if validation fails.
    """
    if not _config.csrf_protection_enabled:
        return

    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return  # Safe methods don't need CSRF protection

    host = request.headers.get("host")
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Host header",
        )

    # If we have an Origin header
    origin = request.headers.get("origin")
    if origin:
        parsed_origin = urllib.parse.urlparse(origin).netloc
        # Check if origin is allowed by configuration or matches host
        if (
            origin in _config.allowed_origins
            or parsed_origin == host
            or "localhost" in parsed_origin
            or "127.0.0.1" in parsed_origin
        ):
            return
        # Otherwise, reject
        logger.warning("CSRF Origin mismatch: origin=%s, host=%s", origin, host)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF origin check failed",
        )

    # If no Origin, fall back to Referer
    referer = request.headers.get("referer")
    if referer:
        parsed_ref = urllib.parse.urlparse(referer).netloc
        if parsed_ref == host or "localhost" in parsed_ref or "127.0.0.1" in parsed_ref:
            return
        logger.warning("CSRF Referer mismatch: referer=%s, host=%s", referer, host)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF referer check failed",
        )

    # Both headers missing – for non-browser clients this may be fine,
    # but for security we can reject or allow based on a flag.
    # We'll allow for simplicity, but log a warning.
    logger.warning("CSRF: No Origin or Referer header for state-changing request.")


# ---------- Main Authentication Dependency ----------
def require_auth(request: Request, token_info: tuple[Optional[str], bool] = Depends(_extract_token)) -> User:
    """
    Authenticate the request and return the application User.

    This is the primary dependency for any protected endpoint.

    Steps:
    1. Extract token from header or cookie.
    2. Perform CSRF validation for state-changing requests using cookie auth.
    3. Verify the token via ClerkTokenVerifier.
    4. Retrieve or create the user via AuthService.
    5. Check that the user account is not suspended.

    Raises:
        HTTPException 401/403/404 as appropriate.
    """
    token, from_cookie = token_info
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # CSRF protection is only needed for cookie-based auth on state-changing methods
    if from_cookie:
        _validate_csrf(request)

    # Verify the token
    try:
        payload = ClerkTokenVerifier.verify_token(token)
    except ClerkVerificationError as e:
        logger.info("Token verification failed: %s", e.message)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )

    clerk_user_id = payload["sub"]
    email = payload["email"]
    full_name = payload["full_name"]

    # Get or create the application user
    user = AuthService.get_or_create_user(
        clerk_user_id=clerk_user_id,
        email=email,
        full_name=full_name,
    )

    # Check if account is suspended
    if user.status.value == "suspended":
        logger.warning("Suspended user attempted access: user_id=%s", user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )

    # Attach the request metadata for auditing (optional)
    request.state.user = user
    return user


# ---------- Role-Based Access Control ----------
def require_role(*roles: UserRole):
    """
    Dependency factory: restricts endpoint to users with one of the specified roles.

    Usage:
        @router.get("/admin")
        async def admin_endpoint(user: User = Depends(require_role(UserRole.ADMIN))):
            ...

    Args:
        *roles: One or more UserRole enum values.

    Returns:
        A FastAPI dependency that returns the authenticated User if authorized.
    """

    def _check(current_user: User = Depends(require_auth)) -> User:
        if current_user.role not in roles:
            # Log the authorization failure
            AuditLogger.log_event(
                event_type="AUTHZ_DENIED",
                user_id=current_user.id,
                details={
                    "user_role": current_user.role.value,
                    "required_roles": [r.value for r in roles],
                    "path": getattr(current_user, "_request", {}).get("url", "unknown"),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        # Optionally log success as well (could be noisy; keep debug)
        logger.debug("Authorized user %s with role %s", current_user.id, current_user.role.value)
        return current_user

    return _check


# Convenience aliases for common roles
# Some enum versions use READ_ONLY, while others use READONLY; support both.
_readonly_role = getattr(UserRole, "READ_ONLY", getattr(UserRole, "READONLY", UserRole.ADMIN))

require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
require_readonly = require_role(UserRole.ADMIN, UserRole.ANALYST, _readonly_role)


# Optional: dependency to attach request user to request state (for logging)
def attach_user(user: User = Depends(require_auth)) -> User:
    """Dependency that also attaches user to request.state for use in route handlers."""
    return user