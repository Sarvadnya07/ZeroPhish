"""
Security Audit Logger for ZeroPhish.

Provides structured security event logging across all security domains.
Events are emitted to the "security.*" logger namespace.

LOG FORMAT: EVENT_TYPE key=value key=value
NEVER LOG: passwords, raw tokens, API keys, TOTP secrets, raw Authorization headers.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

# Root security logger - all security events use "security.*" namespace
_LOG = logging.getLogger("security")


def _evt(logger_name: str, level: int, event_type: str, **fields: Any) -> None:
    """Emit a structured security event log line."""
    log = logging.getLogger(f"security.{logger_name}")
    if not log.isEnabledFor(level):
        return
    parts = [event_type]
    for k, v in fields.items():
        parts.append(f"{k}={v}")
    log.log(level, " ".join(parts))


# ── Authentication events ─────────────────────────────────────────────────────

def log_login_success(user_id: str, role: str, ip: Optional[str] = None) -> None:
    _evt("auth", logging.INFO, "AUTH_LOGIN_SUCCESS",
         user_id=user_id, role=role, ip=ip or "unknown")


def log_login_failure(reason: str, email_domain: Optional[str] = None, user_id: Optional[str] = None, ip: Optional[str] = None) -> None:
    """Log failed login. Never log the full email or password."""
    _evt("auth", logging.WARNING, "AUTH_LOGIN_FAILED",
         reason=reason,
         domain=email_domain or "[unknown]",
         user_id=user_id or "[none]",
         ip=ip or "unknown")


def log_logout(user_id: str, ip: Optional[str] = None) -> None:
    _evt("auth", logging.INFO, "AUTH_LOGOUT", user_id=user_id, ip=ip or "unknown")


def log_register(user_id: str, role: str, ip: Optional[str] = None) -> None:
    _evt("auth", logging.INFO, "AUTH_REGISTER", user_id=user_id, role=role, ip=ip or "unknown")


def log_mfa_success(user_id: str) -> None:
    _evt("auth", logging.INFO, "AUTH_MFA_SUCCESS", user_id=user_id)


def log_mfa_failure(user_id: str, reason: str = "invalid_code") -> None:
    _evt("auth", logging.WARNING, "AUTH_MFA_FAILED", user_id=user_id, reason=reason)


# ── Authorization events ──────────────────────────────────────────────────────

def log_authz_denied(user_id: str, resource: str, action: str, reason: str = "") -> None:
    _evt("authz", logging.WARNING, "AUTHZ_DENIED",
         user_id=user_id, resource=resource, action=action, reason=reason)


def log_authz_csrf_blocked(request_path: str, origin: Optional[str] = None) -> None:
    """Log blocked CSRF — never log full origin if it could contain credentials."""
    safe_origin = (origin or "")[:100]  # truncate long/suspicious origins
    _evt("authz", logging.WARNING, "AUTHZ_CSRF_BLOCKED",
         path=request_path, origin=safe_origin)


def log_admin_action(admin_id: str, action: str, target_id: Optional[str] = None) -> None:
    _evt("authz", logging.INFO, "ADMIN_ACTION",
         admin_id=admin_id, action=action, target_id=target_id or "[none]")


# ── Rate limit events ─────────────────────────────────────────────────────────

def log_rate_limited(ip: str, endpoint: str) -> None:
    _evt("ratelimit", logging.WARNING, "RATE_LIMIT_HIT", ip=ip, endpoint=endpoint)


# ── SSRF events ───────────────────────────────────────────────────────────────

def log_ssrf_blocked(url_host: str, reason: str, ip: Optional[str] = None) -> None:
    """Log a blocked SSRF attempt. url_host should be hostname only, not full URL."""
    _evt("ssrf", logging.WARNING, "SSRF_BLOCKED",
         host=url_host[:200], reason=reason, ip=ip or "unknown")


# ── Upload events ─────────────────────────────────────────────────────────────

def log_upload_rejected(reason: str, filename: Optional[str] = None, size: Optional[int] = None, ip: Optional[str] = None) -> None:
    """Log a rejected upload. Only log safe metadata, not file contents."""
    _evt("upload", logging.WARNING, "UPLOAD_REJECTED",
         reason=reason,
         filename=(filename or "")[:100],
         size=size or 0,
         ip=ip or "unknown")


def log_upload_accepted(filename_safe: str, size: int, content_type: str) -> None:
    _evt("upload", logging.INFO, "UPLOAD_ACCEPTED",
         filename=filename_safe[:100], size=size, content_type=content_type[:80])


# ── Webhook events ────────────────────────────────────────────────────────────

def log_webhook_delivery_failed(sub_id: str, event: str, attempt: int, reason: str) -> None:
    """Log webhook delivery failure. Never log webhook secret."""
    _evt("webhook", logging.WARNING, "WEBHOOK_DELIVERY_FAILED",
         sub_id=sub_id, event=event, attempt=attempt, reason=reason[:200])


def log_webhook_ssrf_blocked(sub_id: str, host: str) -> None:
    _evt("webhook", logging.WARNING, "WEBHOOK_SSRF_BLOCKED",
         sub_id=sub_id, host=host[:200])


# ── Configuration / startup events ───────────────────────────────────────────

def log_config_error(component: str, message: str) -> None:
    _evt("config", logging.CRITICAL, "CONFIG_ERROR",
         component=component, message=message[:500])


def log_startup_warning(component: str, message: str) -> None:
    _evt("config", logging.WARNING, "STARTUP_WARNING",
         component=component, message=message[:500])
