"""
ZeroPhish Clerk Authentication & Token Verification Engine.
Handles cryptographic verification of Clerk session tokens (JWTs).

This module provides a secure token verifier that can validate Clerk-issued
JWTs using either a local public key (PEM) or a JWKS endpoint. It also
supports test mode for unit and integration testing.

Key features:
- RS256/ES256 JWT verification with local public key
- Support for multiple authorized parties (azp) including Chrome extensions
- Graceful fallback for development environments (no signature verification)
- Structured error types and detailed logging
- Test token support for deterministic testing
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import jwt  # type: ignore[import-not-found]
    from jwt import ExpiredSignatureError, InvalidTokenError, InvalidKeyError  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - runtime dependency may be absent in some environments
    jwt = None  # type: ignore[assignment]

    class ExpiredSignatureError(Exception):
        pass

    class InvalidTokenError(Exception):
        pass

    class InvalidKeyError(Exception):
        pass

logger = logging.getLogger(__name__)


# ---------- Custom Exceptions ----------
class ClerkVerificationError(Exception):
    """Raised when Clerk session token verification fails."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ClerkConfigurationError(Exception):
    """Raised when Clerk configuration is invalid or missing."""
    pass


# ---------- Configuration Data Class ----------
@dataclass(frozen=True)
class ClerkConfig:
    """Immutable configuration for Clerk token verification."""

    jwt_key: Optional[str] = None
    issuer: Optional[str] = None
    authorized_parties: Optional[List[str]] = None
    algorithm_whitelist: tuple = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
    env: str = "development"
    test_mode: bool = False

    def __post_init__(self):
        if self.authorized_parties is None:
            # Default authorized parties for local development
            object.__setattr__(
                self,
                "authorized_parties",
                [
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                    "http://localhost:8000",
                    "http://localhost:8001",
                    "http://127.0.0.1:8000",
                    "http://127.0.0.1:8001",
                ]
            )

    @classmethod
    def from_env(cls) -> ClerkConfig:
        """Load configuration from environment variables."""
        env = os.getenv("ENV", "development").lower()
        test_mode = os.getenv("ZEROPHISH_TEST_AUTH", "false").lower() == "true"

        # Load JWT key
        raw_key = os.getenv("CLERK_JWT_KEY")
        if raw_key:
            raw_key = raw_key.strip()
            # Handle single-line PEM with literal \n
            if "\\n" in raw_key and "\n" not in raw_key:
                raw_key = raw_key.replace("\\n", "\n")
            # Auto-wrap if missing headers
            if not raw_key.startswith("-----BEGIN"):
                raw_key = f"-----BEGIN PUBLIC KEY-----\n{raw_key}\n-----END PUBLIC KEY-----"

        # Load authorized parties
        raw_parties = os.getenv("CLERK_AUTHORIZED_PARTIES", "")
        if raw_parties:
            authorized_parties = [p.strip() for p in raw_parties.split(",") if p.strip()]
        else:
            authorized_parties = None  # Will use defaults

        return cls(
            jwt_key=raw_key,
            issuer=os.getenv("CLERK_ISSUER"),
            authorized_parties=authorized_parties,
            env=env,
            test_mode=test_mode,
        )


# ---------- Token Verifier ----------
class ClerkTokenVerifier:
    """
    Verifies Clerk session tokens (JWTs).

    Supports two modes:
    1. **Production mode**: Validates signature using CLERK_JWT_KEY (PEM).
    2. **Development mode**: Verifies token structure/expiry but skips signature validation
       (only when ENV != 'production' and no CLERK_JWT_KEY is set).

    Always validates:
    - Expiration (exp claim)
    - Not-before (nbf claim)
    - Subject (sub claim)
    - Authorized Party (azp) if provided and configured
    """

    config: ClerkConfig = ClerkConfig.from_env()

    @classmethod
    def verify_token(cls, token: str) -> Dict[str, Any]:
        """
        Verify a Clerk session token and return normalized claims.

        Args:
            token: JWT string (may include 'Bearer ' prefix).

        Returns:
            Normalized payload with keys: sub, email, full_name, claims (raw).

        Raises:
            ClerkVerificationError: If verification fails (expired, invalid, etc.).
        """
        if not token or not isinstance(token, str):
            raise ClerkVerificationError("Missing or invalid token format")

        # Remove 'Bearer ' prefix if present
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        if not token:
            raise ClerkVerificationError("Empty bearer token")

        # Test mode override
        if cls.config.test_mode:
            return cls._verify_test_token(token)

        # Production path: use local public key if configured
        if cls.config.jwt_key:
            return cls._verify_with_key(token, cls.config.jwt_key)

        # Development fallback: verify claims only (no signature)
        if cls.config.env != "production":
            logger.warning("⚠️  No CLERK_JWT_KEY set; verifying token structure only (not signature).")
            return cls._verify_claims_only(token)

        # If production but no key, fail loudly
        raise ClerkVerificationError(
            "Production environment requires CLERK_JWT_KEY to be configured."
        )

    @classmethod
    def _verify_with_key(cls, token: str, key: str) -> Dict[str, Any]:
        """
        Perform full JWT verification using a local public key (PEM).

        Args:
            token: JWT string.
            key: PEM-encoded public key.

        Returns:
            Normalized payload.

        Raises:
            ClerkVerificationError: On any verification failure.
        """
        if jwt is None:
            raise ClerkVerificationError("JWT library not available")

        try:
            # Step 1: Inspect algorithm from header
            try:
                unverified_headers = jwt.get_unverified_header(token)
            except Exception as e:
                raise ClerkVerificationError(f"Malformed JWT header: {e}")

            alg = unverified_headers.get("alg")
            if alg not in cls.config.algorithm_whitelist:
                raise ClerkVerificationError(
                    f"Unsupported token algorithm: {alg}. Allowed: {cls.config.algorithm_whitelist}"
                )

            # Step 2: Prepare decode options
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "require": ["exp", "sub"],
            }

            decode_kwargs: Dict[str, Any] = {
                "key": key,
                "algorithms": [alg],
                "options": options,
            }
            if cls.config.issuer:
                decode_kwargs["issuer"] = cls.config.issuer

            # Step 3: Decode and verify
            payload = jwt.decode(token, **decode_kwargs)

            # Step 4: Validate authorized party (azp)
            cls._validate_authorized_party(payload)

            # Step 5: Normalize and return
            return cls._normalize_payload(payload)

        except ExpiredSignatureError:
            logger.warning("Token expired")
            raise ClerkVerificationError("Session token has expired")
        except InvalidTokenError as e:
            logger.warning("Invalid token: %s", e)
            raise ClerkVerificationError(f"Invalid session token: {str(e)}")
        except InvalidKeyError as e:
            logger.error("Invalid public key configuration: %s", e)
            raise ClerkVerificationError("Server configuration error")
        except Exception as e:
            logger.error("Unexpected token verification error: %s", e)
            raise ClerkVerificationError(f"Token verification failed: {str(e)}")

    @classmethod
    def _verify_claims_only(cls, token: str) -> Dict[str, Any]:
        """
        Verify only the token's claims (exp, nbf, sub) without signature validation.
        Used only in development environments.
        """
        if jwt is None:
            raise ClerkVerificationError("JWT library not available")

        try:
            # Decode without signature verification but validate claims
            payload = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "require": ["exp", "sub"],
                },
                algorithms=["RS256", "ES256", "HS256"],  # broad support for dev
            )
            # Validate azp if present
            cls._validate_authorized_party(payload)
            return cls._normalize_payload(payload)
        except ExpiredSignatureError:
            raise ClerkVerificationError("Session token has expired")
        except InvalidTokenError as e:
            raise ClerkVerificationError(f"Invalid token claims: {str(e)}")
        except Exception as e:
            raise ClerkVerificationError(f"Token claim verification failed: {str(e)}")

    @classmethod
    def _validate_authorized_party(cls, payload: Dict[str, Any]) -> None:
        """
        Validate the 'azp' (Authorized Party) claim against the configured allowlist.

        Raises:
            ClerkVerificationError: If azp is present and not allowed.
        """
        azp = payload.get("azp")
        if not azp:
            return  # No azp claim -> no validation required

        allowed_parties = cls.config.authorized_parties
        if not allowed_parties:
            return  # No restriction configured

        # Special case: if any allowed party is 'chrome-extension://*', allow any chrome-extension
        chrome_wildcard = "chrome-extension://*"
        if chrome_wildcard in allowed_parties and azp.startswith("chrome-extension://"):
            return

        # Direct match
        if azp in allowed_parties:
            return

        # Also allow exact matches for localhost variations (just a safety)
        # (If we have http://localhost:3000, also allow http://127.0.0.1:3000? Probably already there)
        # No additional logic needed; we just raise if not found.
        logger.warning("Token azp '%s' not in authorized parties: %s", azp, allowed_parties)
        raise ClerkVerificationError(f"Invalid authorized party: {azp}")

    @classmethod
    def _normalize_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and normalize user claims from the JWT payload.

        Returns a dict with:
            - sub: User ID (string)
            - email: Primary email address
            - full_name: User's full name (fallback to email prefix)
            - claims: The original raw payload
        """
        sub = payload.get("sub")
        if not sub:
            raise ClerkVerificationError("Token missing 'sub' subject claim")

        # Determine email
        email = (
            payload.get("email")
            or payload.get("email_address")
            or (
                payload.get("email_addresses")
                and isinstance(payload.get("email_addresses"), list)
                and payload["email_addresses"]
                and payload["email_addresses"][0].get("email_address")
            )
            or f"{sub}@clerk.user"
        )
        email = str(email).strip()

        # Determine full name
        first_name = payload.get("first_name") or ""
        last_name = payload.get("last_name") or ""
        full_name = (
            payload.get("name")
            or payload.get("full_name")
            or (first_name + " " + last_name).strip()
            or email.split("@")[0]
        )
        full_name = str(full_name).strip()

        return {
            "sub": str(sub),
            "email": email,
            "full_name": full_name,
            "claims": payload,  # retain full payload for downstream
        }

    @classmethod
    def _verify_test_token(cls, token: str) -> Dict[str, Any]:
        """
        Verify test tokens used in unit/integration testing.

        Supports two formats:
        1. 'test_token_<user_id>_<role>' (e.g., test_token_alice_admin)
        2. Any JWT (decoded without signature verification)
        """
        # Format: test_token_user_role
        if token.startswith("test_token_"):
            raw = token[len("test_token_"):]
            if "_" in raw:
                user_id, role = raw.rsplit("_", 1)
            else:
                user_id, role = raw, "user"
            return {
                "sub": f"user_clerk_{user_id}",
                "email": f"{user_id}@example.com",
                "full_name": f"Test User {user_id.capitalize()}",
                "claims": {"role": role, "sub": f"user_clerk_{user_id}"},
            }

        # Otherwise, attempt to decode as JWT (no verification)
        if jwt is None:
            raise ClerkVerificationError("JWT library not available")
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
                algorithms=["RS256", "HS256"],
            )
            return cls._normalize_payload(payload)
        except Exception as e:
            raise ClerkVerificationError(f"Invalid test token: {e}")


# ---------- Convenience function for FastAPI dependency ----------
def verify_token(token: str) -> Dict[str, Any]:
    """Dependency-friendly wrapper for ClerkTokenVerifier.verify_token."""
    return ClerkTokenVerifier.verify_token(token)