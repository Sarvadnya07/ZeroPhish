"""ZeroPhish Authentication & Identity Module."""

from .middleware import require_auth, require_role
from .models import Token, User, UserCreate, UserLogin, UserRole
from .service import AuthService

__all__ = [
    "User",
    "UserRole",
    "UserCreate",
    "UserLogin",
    "Token",
    "AuthService",
    "require_auth",
    "require_role",
]
