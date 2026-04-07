"""
FastAPI dependency utilities for auth enforcement.
"""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import User, UserRole
from .service import AuthService

_bearer = HTTPBearer(auto_error=False)


def _get_token(credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer)) -> Optional[str]:
    if not credentials:
        return None
    return credentials.credentials


def require_auth(token: Optional[str] = Depends(_get_token)) -> User:
    """Dependency: validates bearer token, returns the authenticated User."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user_db = AuthService.validate_token(token)
    if not user_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired or invalid")
    from .models import UserInDB
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
require_admin   = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
