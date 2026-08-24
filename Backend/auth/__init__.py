"""ZeroPhish Authentication & Identity Module (Clerk-integrated)."""

from .clerk import ClerkTokenVerifier, ClerkVerificationError
from .middleware import require_admin, require_analyst, require_auth, require_role
from .models import User, UserInDB, UserRole, UserStatus, UserUpdate
from .service import AuthService

__all__ = [
    "User",
    "UserInDB",
    "UserRole",
    "UserStatus",
    "UserUpdate",
    "AuthService",
    "ClerkTokenVerifier",
    "ClerkVerificationError",
    "require_auth",
    "require_role",
    "require_admin",
    "require_analyst",
]
