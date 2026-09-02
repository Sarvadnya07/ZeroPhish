"""
Centralized, Typed Staging Configuration & Fail-Closed Validation for Phase 13.3.

Enforces strict environment checks, explicit staging host allowlists,
production target rejection, and granular network timeout budgets.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ---------- Constants ----------
FORBIDDEN_PRODUCTION_HOSTS = [
    "zerophish.com",
    "app.zerophish.com",
    "api.zerophish.com",
    "prod.zerophish.com",
]
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 15.0
DEFAULT_WRITE_TIMEOUT = 10.0
DEFAULT_POOL_TIMEOUT = 5.0
DEFAULT_REQUEST_TIMEOUT = 20.0
DEFAULT_MAX_RUNTIME = 300.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5
DEFAULT_MAX_ERRORS = 10
DEFAULT_PROGRESS_EVERY = 100
DEFAULT_CONCURRENCY = 20


# ---------- Configuration Model ----------
class ExternalStagingConfig(BaseModel):
    """
    Validated external staging client configuration.

    All timeouts are in seconds. Credentials (api_token, username, password)
    are optional and never logged.
    """

    zerophish_env: str = Field(..., description="Must be 'staging'")
    staging_base_url: str = Field(..., description="Absolute HTTP(S) URL of deployed staging gateway")
    staging_allowed_hosts: List[str] = Field(
        default_factory=list, description="Explicit staging host allowlist"
    )

    # Timeouts (Seconds)
    connect_timeout_sec: float = Field(default=DEFAULT_CONNECT_TIMEOUT, ge=0.1, le=60.0)
    read_timeout_sec: float = Field(default=DEFAULT_READ_TIMEOUT, ge=0.1, le=120.0)
    write_timeout_sec: float = Field(default=DEFAULT_WRITE_TIMEOUT, ge=0.1, le=60.0)
    pool_timeout_sec: float = Field(default=DEFAULT_POOL_TIMEOUT, ge=0.1, le=30.0)
    request_timeout_sec: float = Field(default=DEFAULT_REQUEST_TIMEOUT, ge=0.1, le=300.0)
    max_runtime_sec: float = Field(default=DEFAULT_MAX_RUNTIME, ge=1.0, le=3600.0)

    # Retry & Error Budget
    max_retries: int = Field(default=DEFAULT_MAX_RETRIES, ge=0, le=10)
    backoff_base_sec: float = Field(default=DEFAULT_BACKOFF_BASE, ge=0.1, le=5.0)
    max_errors: int = Field(default=DEFAULT_MAX_ERRORS, ge=1, le=1000)
    progress_every: int = Field(default=DEFAULT_PROGRESS_EVERY, ge=1, le=10000)
    concurrency: int = Field(default=DEFAULT_CONCURRENCY, ge=1, le=100)

    # Optional Credentials (Never logged or printed)
    api_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    @field_validator("staging_base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Scheme must be http or https, got: '{parsed.scheme}'")
        if not parsed.netloc:
            raise ValueError(f"Missing hostname: '{v}'")
        return v.rstrip("/")

    def model_dump_safe(self) -> dict:
        """Return a copy of the configuration with credentials redacted."""
        data = self.model_dump()
        if "api_token" in data and data["api_token"]:
            data["api_token"] = "***REDACTED***"
        if "password" in data and data["password"]:
            data["password"] = "***REDACTED***"
        return data


# ---------- Configuration Validator ----------
class ExternalStagingConfigValidator:
    """
    Fail-closed validator for external staging configuration without network requests.

    Loads configuration from environment variables and optionally applies overrides.
    """

    @classmethod
    def load_and_validate(
        cls,
        base_url_override: Optional[str] = None,
        max_runtime_override: Optional[float] = None,
        max_errors_override: Optional[int] = None,
        concurrency_override: Optional[int] = None,
        progress_every_override: Optional[int] = None,
    ) -> Tuple[bool, List[str], Optional[ExternalStagingConfig]]:
        """
        Validate staging configuration from environment with zero network calls.

        Returns:
            (is_valid, error_messages, config_object)
        """
        errors: List[str] = []

        # 1. Validate environment
        env_val = os.getenv("ZEROPHISH_ENV", "").strip().lower()
        if not env_val:
            errors.append("ZEROPHISH_ENV is not configured. Must be set to 'staging'.")
        elif env_val != "staging":
            errors.append(f"ZEROPHISH_ENV must be 'staging', got: '{env_val}'.")

        # 2. Validate base URL
        raw_url = (base_url_override or os.getenv("ZEROPHISH_STAGING_BASE_URL", "")).strip()
        if not raw_url:
            errors.append("ZEROPHISH_STAGING_BASE_URL is not configured.")
        else:
            parsed = urlparse(raw_url)
            if parsed.scheme not in ("http", "https"):
                errors.append(f"Scheme must be http or https, got: '{parsed.scheme}'.")
            if not parsed.netloc or not parsed.hostname:
                errors.append(f"Malformed hostname: '{raw_url}'.")
            else:
                host = parsed.hostname.lower()
                if any(prod in host for prod in FORBIDDEN_PRODUCTION_HOSTS):
                    errors.append(f"SAFETY VIOLATION: Refusing to target production domain '{host}'.")

        # 3. Validate allowed hosts
        raw_allowed = os.getenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "").strip()
        allowed_hosts: List[str] = []
        if raw_allowed:
            allowed_hosts = [h.strip().lower() for h in raw_allowed.split(",") if h.strip()]
        else:
            # If not set, we might still allow localhost for development, but we'll warn.
            errors.append("ZEROPHISH_STAGING_ALLOWED_HOSTS is not configured (recommended for safety).")

        # If base URL has hostname and allowed_hosts is non-empty, verify allowlist
        if raw_url and not any("SAFETY VIOLATION" in e for e in errors):
            parsed_host = (urlparse(raw_url).hostname or "").lower()
            if allowed_hosts and not any(
                parsed_host == a
                or (a.startswith("*.") and parsed_host.endswith(a[1:]))
                or parsed_host.endswith(".internal")
                for a in allowed_hosts
            ):
                errors.append(
                    f"Host '{parsed_host}' not in allowlist {allowed_hosts}."
                )

        if errors:
            logger.error("Configuration validation failed: %s", "; ".join(errors))
            return False, errors, None

        # Load optional timeouts & parameters with defaults
        try:
            connect_t = float(os.getenv("EXTERNAL_STAGING_CONNECT_TIMEOUT_SECONDS", str(DEFAULT_CONNECT_TIMEOUT)))
            read_t = float(os.getenv("EXTERNAL_STAGING_READ_TIMEOUT_SECONDS", str(DEFAULT_READ_TIMEOUT)))
            write_t = float(os.getenv("EXTERNAL_STAGING_WRITE_TIMEOUT_SECONDS", str(DEFAULT_WRITE_TIMEOUT)))
            pool_t = float(os.getenv("EXTERNAL_STAGING_POOL_TIMEOUT_SECONDS", str(DEFAULT_POOL_TIMEOUT)))
            req_t = float(os.getenv("EXTERNAL_STAGING_REQUEST_TIMEOUT_SECONDS", str(DEFAULT_REQUEST_TIMEOUT)))
            max_run = max_runtime_override or float(os.getenv("EXTERNAL_STAGING_MAX_RUNTIME_SECONDS", str(DEFAULT_MAX_RUNTIME)))
            max_retries = int(os.getenv("EXTERNAL_STAGING_MAX_RETRIES", str(DEFAULT_MAX_RETRIES)))
            backoff_base = float(os.getenv("EXTERNAL_STAGING_BACKOFF_BASE_SECONDS", str(DEFAULT_BACKOFF_BASE)))
            max_err = max_errors_override or int(os.getenv("EXTERNAL_STAGING_MAX_ERRORS", str(DEFAULT_MAX_ERRORS)))
            prog_every = progress_every_override or int(os.getenv("EXTERNAL_STAGING_PROGRESS_EVERY", str(DEFAULT_PROGRESS_EVERY)))
            concurrency = concurrency_override or int(os.getenv("EXTERNAL_STAGING_CONCURRENCY", str(DEFAULT_CONCURRENCY)))
        except ValueError as e:
            errors.append(f"Invalid numeric environment variable: {e}")
            return False, errors, None

        # Build config object (Pydantic will validate again)
        try:
            cfg = ExternalStagingConfig(
                zerophish_env=env_val,
                staging_base_url=raw_url.rstrip("/"),
                staging_allowed_hosts=allowed_hosts,
                connect_timeout_sec=connect_t,
                read_timeout_sec=read_t,
                write_timeout_sec=write_t,
                pool_timeout_sec=pool_t,
                request_timeout_sec=req_t,
                max_runtime_sec=max_run,
                max_retries=max_retries,
                backoff_base_sec=backoff_base,
                max_errors=max_err,
                progress_every=prog_every,
                concurrency=concurrency,
                api_token=os.getenv("ZEROPHISH_STAGING_API_TOKEN"),
                username=os.getenv("ZEROPHISH_STAGING_USERNAME"),
                password=os.getenv("ZEROPHISH_STAGING_PASSWORD"),
            )
        except Exception as e:
            errors.append(f"Configuration validation error: {e}")
            return False, errors, None

        logger.info("Configuration valid: env=%s, base_url=%s, concurrency=%d",
                    cfg.zerophish_env, cfg.staging_base_url, cfg.concurrency)
        return True, [], cfg