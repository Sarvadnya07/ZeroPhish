"""
Centralized, Typed Staging Configuration & Fail-Closed Validation for Phase 13.3.
Enforces strict environment checks, explicit staging host allowlists,
production target rejection, and granular network timeout budgets.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ExternalStagingConfig(BaseModel):
    """Validated external staging client configuration."""

    zerophish_env: str = Field(..., description="Must be 'staging'")
    staging_base_url: str = Field(
        ..., description="Absolute HTTP(S) URL of deployed staging gateway"
    )
    staging_allowed_hosts: List[str] = Field(
        default_factory=list, description="Explicit staging host allowlist"
    )

    # Timeouts (Seconds)
    connect_timeout_sec: float = Field(default=5.0, description="TCP/TLS connection timeout")
    read_timeout_sec: float = Field(default=15.0, description="HTTP response read timeout")
    write_timeout_sec: float = Field(default=10.0, description="HTTP request write timeout")
    pool_timeout_sec: float = Field(default=5.0, description="Connection pool acquisition timeout")
    request_timeout_sec: float = Field(default=20.0, description="Hard total per-request deadline")
    max_runtime_sec: float = Field(default=300.0, description="Global run deadline in seconds")

    # Retry & Error Budget
    max_retries: int = Field(
        default=3, description="Maximum bounded retries on transient network errors"
    )
    backoff_base_sec: float = Field(default=0.5, description="Exponential backoff base delay")
    max_errors: int = Field(default=10, description="Error budget threshold before fail-stop")
    progress_every: int = Field(default=100, description="Progress reporting cadence in requests")
    concurrency: int = Field(default=20, description="Maximum concurrent outgoing HTTP requests")

    # Optional Credentials (Never logged or printed)
    api_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class ExternalStagingConfigValidator:
    """Fail-closed validator for external staging configuration without network requests."""

    FORBIDDEN_PRODUCTION_HOSTS = [
        "zerophish.com",
        "app.zerophish.com",
        "api.zerophish.com",
        "prod.zerophish.com",
    ]

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
        Validates staging configuration from environment with zero network calls.
        Returns: (is_valid, error_messages, config_object)
        """
        errors: List[str] = []

        # 1. Validate ZEROPHISH_ENV
        env_val = os.getenv("ZEROPHISH_ENV", "").strip().lower()
        if not env_val:
            errors.append("ZEROPHISH_ENV is not configured. Must be set to 'staging'.")
        elif env_val != "staging":
            errors.append(f"ZEROPHISH_ENV must be 'staging', got: '{env_val}'.")

        # 2. Validate ZEROPHISH_STAGING_BASE_URL
        raw_url = (base_url_override or os.getenv("ZEROPHISH_STAGING_BASE_URL", "")).strip()
        if not raw_url:
            errors.append("ZEROPHISH_STAGING_BASE_URL is not configured.")
        else:
            parsed = urlparse(raw_url)
            if parsed.scheme not in ("http", "https"):
                errors.append(
                    f"ZEROPHISH_STAGING_BASE_URL must have http or https scheme, got: '{parsed.scheme}'."
                )
            if not parsed.netloc or not parsed.hostname:
                errors.append(
                    f"ZEROPHISH_STAGING_BASE_URL has missing or malformed hostname: '{raw_url}'."
                )
            else:
                host = parsed.hostname.lower()
                # Check forbidden production hostnames
                if any(prod in host for prod in cls.FORBIDDEN_PRODUCTION_HOSTS):
                    errors.append(
                        f"SAFETY VIOLATION: Refusing to target production domain '{host}'."
                    )

        # 3. Validate ZEROPHISH_STAGING_ALLOWED_HOSTS
        raw_allowed = os.getenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "").strip()
        allowed_hosts: List[str] = []
        if raw_allowed:
            allowed_hosts = [h.strip().lower() for h in raw_allowed.split(",") if h.strip()]
        else:
            # If not explicitly set in env, check if standard local/staging host is configured
            errors.append("ZEROPHISH_STAGING_ALLOWED_HOSTS is not configured.")

        # If base URL has a hostname and allowed_hosts is populated, verify allowlist
        if raw_url and not any("SAFETY VIOLATION" in e for e in errors):
            parsed_host = (urlparse(raw_url).hostname or "").lower()
            if allowed_hosts and not any(
                parsed_host == a
                or (a.startswith("*.") and parsed_host.endswith(a[1:]))
                or parsed_host.endswith(".internal")
                for a in allowed_hosts
            ):
                errors.append(
                    f"Staging hostname '{parsed_host}' is not present in ZEROPHISH_STAGING_ALLOWED_HOSTS {allowed_hosts}."
                )

        if errors:
            return False, errors, None

        # Load optional timeouts & parameters
        connect_t = float(os.getenv("EXTERNAL_STAGING_CONNECT_TIMEOUT_SECONDS", "5.0"))
        read_t = float(os.getenv("EXTERNAL_STAGING_READ_TIMEOUT_SECONDS", "15.0"))
        write_t = float(os.getenv("EXTERNAL_STAGING_WRITE_TIMEOUT_SECONDS", "10.0"))
        pool_t = float(os.getenv("EXTERNAL_STAGING_POOL_TIMEOUT_SECONDS", "5.0"))
        req_t = float(os.getenv("EXTERNAL_STAGING_REQUEST_TIMEOUT_SECONDS", "20.0"))
        max_run = max_runtime_override or float(
            os.getenv("EXTERNAL_STAGING_MAX_RUNTIME_SECONDS", "300.0")
        )
        max_retries = int(os.getenv("EXTERNAL_STAGING_MAX_RETRIES", "3"))
        backoff_base = float(os.getenv("EXTERNAL_STAGING_BACKOFF_BASE_SECONDS", "0.5"))
        max_err = max_errors_override or int(os.getenv("EXTERNAL_STAGING_MAX_ERRORS", "10"))
        prog_every = progress_every_override or int(
            os.getenv("EXTERNAL_STAGING_PROGRESS_EVERY", "100")
        )
        concurrency = concurrency_override or int(os.getenv("EXTERNAL_STAGING_CONCURRENCY", "20"))

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

        return True, [], cfg
