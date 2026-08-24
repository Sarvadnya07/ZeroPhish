"""
ZeroPhish Clerk Authentication & Token Verification Engine.
Handles cryptographic verification of Clerk session tokens.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

logger = logging.getLogger(__name__)


class ClerkVerificationError(Exception):
    """Raised when Clerk session token verification fails."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ClerkTokenVerifier:
    """
    Verifies Clerk session tokens (JWTs) using either:
    1. Local public key verification via CLERK_JWT_KEY (PEM formatted RS256/ES256 key)
    2. JWKS or Clerk backend API verification
    """

    @classmethod
    def get_jwt_key(cls) -> Optional[str]:
        raw_key = os.getenv("CLERK_JWT_KEY")
        if not raw_key:
            return None
        raw_key = raw_key.strip()
        # Handle single-line formatted PEM keys with literal \n
        if "\\n" in raw_key and "\n" not in raw_key:
            raw_key = raw_key.replace("\\n", "\n")
        if not raw_key.startswith("-----BEGIN"):
            raw_key = f"-----BEGIN PUBLIC KEY-----\n{raw_key}\n-----END PUBLIC KEY-----"
        return raw_key

    @classmethod
    def get_authorized_parties(cls) -> List[str]:
        raw = os.getenv("CLERK_AUTHORIZED_PARTIES", "")
        if not raw:
            return [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:8000",
                "http://localhost:8001",
                "http://127.0.0.1:8000",
                "http://127.0.0.1:8001",
            ]
        return [p.strip() for p in raw.split(",") if p.strip()]

    @classmethod
    def verify_token(cls, token: str) -> Dict[str, Any]:
        if not token or not isinstance(token, str):
            raise ClerkVerificationError("Missing or invalid token format")

        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        if not token:
            raise ClerkVerificationError("Empty bearer token")

        # ── Test Environment Token Handling ─────────────────────────────────────
        # For unit testing without external network access, support mock test tokens
        if os.getenv("ZEROPHISH_TEST_AUTH", "false").lower() == "true":
            return cls._verify_test_token(token)

        jwt_key = cls.get_jwt_key()

        # If CLERK_JWT_KEY is configured, use cryptographically secure local verification
        if jwt_key:
            try:
                # Unverified header inspection to check algorithm
                unverified_headers = jwt.get_unverified_header(token)
                alg = unverified_headers.get("alg")
                if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
                    raise ClerkVerificationError(f"Unsupported token algorithm: {alg}")

                options = {
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "require": ["exp", "sub"],
                }

                issuer = os.getenv("CLERK_ISSUER")
                decode_kwargs: Dict[str, Any] = {
                    "key": jwt_key,
                    "algorithms": [alg],
                    "options": options,
                }
                if issuer:
                    decode_kwargs["issuer"] = issuer

                payload = jwt.decode(token, **decode_kwargs)

                # Validate Authorized Party (azp) if present and configured
                azp = payload.get("azp")
                authorized_parties = cls.get_authorized_parties()
                if azp and authorized_parties and azp not in authorized_parties:
                    if not any(
                        azp.startswith("chrome-extension://")
                        for ap in authorized_parties
                        if ap == "chrome-extension://*"
                    ):
                        logger.warning("Token azp mismatch: %s not in %s", azp, authorized_parties)
                        raise ClerkVerificationError(f"Invalid authorized party: {azp}")

                return cls._normalize_payload(payload)

            except ExpiredSignatureError:
                raise ClerkVerificationError("Session token has expired")
            except InvalidTokenError as e:
                raise ClerkVerificationError(f"Invalid session token: {str(e)}")
            except Exception as e:
                logger.error("Token verification error: %s", e)
                raise ClerkVerificationError(f"Token verification failed: {str(e)}")

        # Fallback in local development without key: verify token structure and claims
        if os.getenv("ENV", "development") != "production":
            try:
                payload = jwt.decode(
                    token,
                    options={
                        "verify_signature": False,
                        "verify_exp": True,
                        "verify_nbf": True,
                        "require": ["exp", "sub"],
                    },
                    algorithms=["RS256", "ES256", "HS256"],
                )
                return cls._normalize_payload(payload)
            except ExpiredSignatureError:
                raise ClerkVerificationError("Session token has expired")
            except Exception as e:
                raise ClerkVerificationError(f"Invalid token: {str(e)}")

        raise ClerkVerificationError("Backend missing CLERK_JWT_KEY verification configuration")

    @classmethod
    def _normalize_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        sub = payload.get("sub")
        if not sub:
            raise ClerkVerificationError("Token missing 'sub' subject claim")

        email = (
            payload.get("email")
            or payload.get("email_address")
            or (payload.get("email_addresses") or [{}])[0].get("email_address", "")
            or f"{sub}@clerk.user"
        )
        name = (
            payload.get("name")
            or payload.get("full_name")
            or f"{payload.get('first_name', '')} {payload.get('last_name', '')}".strip()
            or email.split("@")[0]
        )

        return {
            "sub": str(sub),
            "email": str(email),
            "full_name": str(name),
            "claims": payload,
        }

    @classmethod
    def _verify_test_token(cls, token: str) -> Dict[str, Any]:
        """Support deterministic test tokens for unit and integration testing."""
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
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
                algorithms=["RS256", "HS256"],
            )
            return cls._normalize_payload(payload)
        except Exception as e:
            raise ClerkVerificationError(f"Invalid test token: {e}")
