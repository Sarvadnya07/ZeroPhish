"""
Security Audit Logger for ZeroPhish.

Provides structured security event logging across all security domains.
Events are emitted to the "security.*" logger namespace with structured key=value format.

NEVER LOG: passwords, raw tokens, API keys, TOTP secrets, raw Authorization headers.

All sensitive fields are automatically redacted.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, Optional


# ---------- Constants ----------
DEFAULT_IP = "unknown"
MAX_STRING_LENGTH = 500
REDACTED = "[REDACTED]"


# ---------- Enums ----------
class SecurityEventType(str, Enum):
    """All security event types for consistent logging."""
    # Authentication
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_REGISTER = "AUTH_REGISTER"
    AUTH_MFA_SUCCESS = "AUTH_MFA_SUCCESS"
    AUTH_MFA_FAILED = "AUTH_MFA_FAILED"
    # Authorization
    AUTHZ_DENIED = "AUTHZ_DENIED"
    AUTHZ_CSRF_BLOCKED = "AUTHZ_CSRF_BLOCKED"
    ADMIN_ACTION = "ADMIN_ACTION"
    # Rate limiting
    RATE_LIMIT_HIT = "RATE_LIMIT_HIT"
    # Security controls
    SSRF_BLOCKED = "SSRF_BLOCKED"
    UPLOAD_REJECTED = "UPLOAD_REJECTED"
    UPLOAD_ACCEPTED = "UPLOAD_ACCEPTED"
    # Webhooks
    WEBHOOK_DELIVERY_FAILED = "WEBHOOK_DELIVERY_FAILED"
    WEBHOOK_SSRF_BLOCKED = "WEBHOOK_SSRF_BLOCKED"
    # Configuration
    CONFIG_ERROR = "CONFIG_ERROR"
    STARTUP_WARNING = "STARTUP_WARNING"
    # General
    USER_PROVISIONED = "USER_PROVISIONED"
    AUDIT_EVENT = "AUDIT_EVENT"


# ---------- Logger Core ----------
_root_log = logging.getLogger("security")


def _emit_logger(
    event_type: str,
    level: int,
    sub_namespace: str,
    **fields: Any,
) -> None:
    """
    Emit a structured security event log.

    All fields are sanitised: strings are truncated and sensitive keys redacted.
    """
    log = logging.getLogger(f"security.{sub_namespace}")
    if not log.isEnabledFor(level):
        return

    # Sanitise fields
    sanitised = {}
    for k, v in fields.items():
        # Redact known sensitive keys
        if k.lower() in (
            "password",
            "token",
            "api_key",
            "apikey",
            "secret",
            "totp",
            "auth",
            "authorization",
        ):
            sanitised[k] = REDACTED
            continue

        if isinstance(v, str):
            # Truncate long strings to avoid log explosion
            if len(v) > MAX_STRING_LENGTH:
                v = v[:MAX_STRING_LENGTH] + "..."
            # Remove newlines and control chars for single-line logs
            v = " ".join(v.splitlines())
            sanitised[k] = v
        elif v is None:
            sanitised[k] = "None"
        else:
            sanitised[k] = str(v)

    # Build log message: event_type key=value key=value
    parts = [event_type]
    for k, v in sanitised.items():
        # If value contains spaces, quote it
        if isinstance(v, str) and (" " in v or "=" in v):
            v = f'"{v}"'
        parts.append(f"{k}={v}")

    log.log(level, " ".join(parts))


# ---------- Convenience Functions ----------
# Authentication events
def log_login_success(
    user_id: str,
    role: str,
    ip: Optional[str] = None,
    method: str = "password",
) -> None:
    _emit_logger(
        SecurityEventType.AUTH_LOGIN_SUCCESS.value,
        logging.INFO,
        "auth",
        user_id=user_id,
        role=role,
        ip=ip or DEFAULT_IP,
        method=method,
    )


def log_login_failure(
    reason: str,
    email_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    _emit_logger(
        SecurityEventType.AUTH_LOGIN_FAILED.value,
        logging.WARNING,
        "auth",
        reason=reason,
        domain=email_domain or "[unknown]",
        user_id=user_id or "[none]",
        ip=ip or DEFAULT_IP,
    )


def log_logout(user_id: str, ip: Optional[str] = None) -> None:
    _emit_logger(
        SecurityEventType.AUTH_LOGOUT.value,
        logging.INFO,
        "auth",
        user_id=user_id,
        ip=ip or DEFAULT_IP,
    )


def log_register(user_id: str, role: str, ip: Optional[str] = None) -> None:
    _emit_logger(
        SecurityEventType.AUTH_REGISTER.value,
        logging.INFO,
        "auth",
        user_id=user_id,
        role=role,
        ip=ip or DEFAULT_IP,
    )


def log_mfa_success(user_id: str, method: str = "totp") -> None:
    _emit_logger(
        SecurityEventType.AUTH_MFA_SUCCESS.value,
        logging.INFO,
        "auth",
        user_id=user_id,
        method=method,
    )


def log_mfa_failure(user_id: str, reason: str = "invalid_code") -> None:
    _emit_logger(
        SecurityEventType.AUTH_MFA_FAILED.value,
        logging.WARNING,
        "auth",
        user_id=user_id,
        reason=reason,
    )


# Authorization events
def log_authz_denied(
    user_id: str,
    resource: str,
    action: str,
    reason: str = "",
    ip: Optional[str] = None,
) -> None:
    _emit_logger(
        SecurityEventType.AUTHZ_DENIED.value,
        logging.WARNING,
        "authz",
        user_id=user_id,
        resource=resource,
        action=action,
        reason=reason or "no_reason",
        ip=ip or DEFAULT_IP,
    )


def log_authz_csrf_blocked(request_path: str, origin: Optional[str] = None) -> None:
    safe_origin = (origin or "")[:100]  # truncate long/suspicious origins
    _emit_logger(
        SecurityEventType.AUTHZ_CSRF_BLOCKED.value,
        logging.WARNING,
        "authz",
        path=request_path,
        origin=safe_origin,
    )


def log_admin_action(admin_id: str, action: str, target_id: Optional[str] = None) -> None:
    _emit_logger(
        SecurityEventType.ADMIN_ACTION.value,
        logging.INFO,
        "authz",
        admin_id=admin_id,
        action=action,
        target_id=target_id or "[none]",
    )


# Rate limit events
def log_rate_limited(ip: str, endpoint: str) -> None:
    _emit_logger(
        SecurityEventType.RATE_LIMIT_HIT.value,
        logging.WARNING,
        "ratelimit",
        ip=ip,
        endpoint=endpoint[:200],
    )


# SSRF events
def log_ssrf_blocked(
    url_host: str,
    reason: str,
    ip: Optional[str] = None,
    source: str = "webhook",
) -> None:
    """Log a blocked SSRF attempt. url_host should be hostname only, not full URL."""
    _emit_logger(
        SecurityEventType.SSRF_BLOCKED.value,
        logging.WARNING,
        "ssrf",
        host=url_host[:200],
        reason=reason,
        ip=ip or DEFAULT_IP,
        source=source,
    )


# Upload events
def log_upload_rejected(
    reason: str,
    filename: Optional[str] = None,
    size: Optional[int] = None,
    ip: Optional[str] = None,
) -> None:
    _emit_logger(
        SecurityEventType.UPLOAD_REJECTED.value,
        logging.WARNING,
        "upload",
        reason=reason,
        filename=(filename or "")[:100],
        size=size or 0,
        ip=ip or DEFAULT_IP,
    )


def log_upload_accepted(filename_safe: str, size: int, content_type: str) -> None:
    _emit_logger(
        SecurityEventType.UPLOAD_ACCEPTED.value,
        logging.INFO,
        "upload",
        filename=filename_safe[:100],
        size=size,
        content_type=content_type[:80],
    )


# Webhook events
def log_webhook_delivery_failed(
    sub_id: str,
    event: str,
    attempt: int,
    reason: str,
    http_status: Optional[int] = None,
) -> None:
    _emit_logger(
        SecurityEventType.WEBHOOK_DELIVERY_FAILED.value,
        logging.WARNING,
        "webhook",
        sub_id=sub_id,
        event=event,
        attempt=attempt,
        reason=reason[:200],
        http_status=http_status or 0,
    )


def log_webhook_ssrf_blocked(sub_id: str, host: str) -> None:
    _emit_logger(
        SecurityEventType.WEBHOOK_SSRF_BLOCKED.value,
        logging.WARNING,
        "webhook",
        sub_id=sub_id,
        host=host[:200],
    )


# Configuration / startup events
def log_config_error(component: str, message: str) -> None:
    _emit_logger(
        SecurityEventType.CONFIG_ERROR.value,
        logging.CRITICAL,
        "config",
        component=component,
        message=message[:500],
    )


def log_startup_warning(component: str, message: str) -> None:
    _emit_logger(
        SecurityEventType.STARTUP_WARNING.value,
        logging.WARNING,
        "config",
        component=component,
        message=message[:500],
    )


# General audit events
class AuditLogger:
    """Static utility for logging general audit events."""

    @staticmethod
    def log_event(
        event_type: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a generic audit event with optional details."""
        safe_details = details or {}
        _emit_logger(
            event_type,
            logging.INFO,
            "audit",
            user_id=user_id or "[none]",
            **safe_details,
        )