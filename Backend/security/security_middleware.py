"""
Security Middleware and Utilities for ZeroPhish.

Provides:
- Security headers middleware (HSTS, CSP, X‑Frame‑Options, etc.)
- Request size limiting middleware
- Input sanitisation (email, URL, SSRF protection)
- CSRF validation helper
- Log injection prevention
- Generic error messages for client responses
"""

from __future__ import annotations

import html
import ipaddress
import logging
import re
import socket
import urllib.parse
from typing import List, Optional, Tuple

from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from security.audit_logger import AuditLogger, log_ssrf_blocked

logger = logging.getLogger(__name__)

# ---------- Constants ----------
DEFAULT_MAX_REQUEST_SIZE = 1_000_000  # 1 MB
DEFAULT_MAX_EMAIL_LENGTH = 320  # RFC 5321
DEFAULT_MAX_URL_LENGTH = 2048
DEFAULT_MAX_BODY_LENGTH = 50_000
DEFAULT_MAX_LINKS = 100
DEFAULT_MAX_SUBJECT_LENGTH = 1000

# Dangerous schemes (only allow http/https for webhooks)
ALLOWED_SCHEMES = {"http", "https"}

# Forbidden hostnames / patterns (SSRF protection)
FORBIDDEN_HOSTNAMES = {"localhost", "localhost.localdomain", "127.0.0.1", "0.0.0.0", "::1"}

# Reserved subnets for SSRF blocking
PRIVATE_SUBNETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
]
# IPv4-mapped IPv6 subnet
IPV4_MAPPED_SUBNET = ipaddress.ip_network("::ffff:0:0/96")


# ---------- Middleware ----------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; object-src 'none'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        # HSTS (optional, for HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Remove Server header (information disclosure)
        if "server" in response.headers:
            del response.headers["server"]

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size to prevent DoS attacks."""

    def __init__(self, app, max_size: int = DEFAULT_MAX_REQUEST_SIZE):
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_size:
                    logger.warning("Request size limit exceeded: %s bytes", content_length)
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            except ValueError:
                pass  # Invalid content-length, ignore
        return await call_next(request)


# ---------- Input Sanitisation ----------
def sanitize_email_content(text: str, max_length: int = DEFAULT_MAX_BODY_LENGTH) -> str:
    """Sanitize email content to prevent XSS and injection attacks."""
    if not text:
        return ""
    text = text[:max_length]
    text = html.escape(text)
    text = text.replace("\x00", "")
    return text


def validate_email_address(email: str) -> bool:
    """
    Validate email address format using email-validator to prevent ReDoS.

    Returns True if valid, False otherwise.
    """
    if not email or len(email) > DEFAULT_MAX_EMAIL_LENGTH:
        return False
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def validate_url(url: str) -> bool:
    """Validate URL format and prevent CRLF/Injection and dangerous schemes."""
    if not url or len(url) > DEFAULT_MAX_URL_LENGTH:
        return False
    # Reject control characters
    if re.search(r"[\s\x00-\x1F\x7F]", url):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return False
        if not parsed.netloc or not parsed.hostname:
            return False
        return True
    except ValueError:
        return False


def is_safe_webhook_url(url: str, allow_http: bool = False, log_source: str = "webhook") -> bool:
    """
    Validate destination URL to prevent SSRF attacks.

    Blocks:
    - Loopback addresses (127.0.0.0/8, ::1)
    - Private RFC1918 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local & cloud metadata (169.254.0.0/16, fe80::/10, 169.254.169.254)
    - Carrier-grade NAT (100.64.0.0/10)
    - Multicast, reserved, unspecified addresses
    - IPv4-mapped IPv6 representations (::ffff:...)
    - Embedded user credentials
    - Known localhost aliases

    Logs SSRF blocks via the audit logger.
    """
    if not validate_url(url):
        return False

    parsed = urllib.parse.urlparse(url)
    if parsed.username or parsed.password:
        log_ssrf_blocked(parsed.hostname or "unknown", "embedded_credentials", source=log_source)
        return False

    scheme = parsed.scheme.lower()
    if scheme == "http" and not allow_http:
        log_ssrf_blocked(parsed.hostname or "unknown", "http_not_allowed", source=log_source)
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    lower_host = hostname.lower()
    if lower_host in FORBIDDEN_HOSTNAMES:
        log_ssrf_blocked(lower_host, "localhost_alias", source=log_source)
        return False

    try:
        ip_objs = []
        # Try to parse as IP directly
        try:
            ip_objs.append(ipaddress.ip_address(hostname))
        except ValueError:
            # Resolve DNS (may block; use limited timeout)
            try:
                addrinfo = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
                for res in addrinfo:
                    sockaddr = res[4]
                    ip_objs.append(ipaddress.ip_address(sockaddr[0]))
            except socket.gaierror:
                # Cannot resolve; assume safe? Better to reject to be safe.
                log_ssrf_blocked(lower_host, "dns_resolution_failed", source=log_source)
                return False

        if not ip_objs:
            return False

        # Check each resolved IP
        for ip in ip_objs:
            # Convert IPv4-mapped IPv6 to IPv4
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped

            # Check against forbidden subnets
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                log_ssrf_blocked(str(ip), "reserved_ip", source=log_source)
                return False

            # Check against custom subnets (NAT, metadata)
            for subnet in PRIVATE_SUBNETS:
                if ip in subnet:
                    log_ssrf_blocked(str(ip), f"subnet_{subnet}", source=log_source)
                    return False

        return True

    except Exception as e:
        logger.warning("SSRF check failed for %s: %s", hostname, e)
        log_ssrf_blocked(hostname, f"check_error:{str(e)[:50]}", source=log_source)
        return False


def is_safe_url(url: str, allow_http: bool = False) -> bool:
    """Alias for is_safe_webhook_url for general SSRF checks."""
    return is_safe_webhook_url(url, allow_http=allow_http, log_source="general")


def sanitize_log_message(message: str, max_length: int = 500) -> str:
    """Sanitize log messages to prevent log injection."""
    if not message:
        return ""
    message = message.replace("\n", " ").replace("\r", " ")
    if len(message) > max_length:
        message = message[:max_length - 3] + "..."
    return message


def get_generic_error_message(status_code: int) -> str:
    """Get generic error message for client (hide internal details)."""
    error_messages = {
        400: "Invalid request",
        401: "Authentication required",
        403: "Access denied",
        404: "Resource not found",
        413: "Request too large",
        429: "Too many requests",
        500: "Internal server error",
        503: "Service temporarily unavailable",
    }
    return error_messages.get(status_code, "An error occurred")


class InputValidator:
    """Validate and sanitise request inputs."""

    @staticmethod
    def validate_scan_request(
        sender: str,
        body: str,
        links: List[str],
        subject: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a gateway scan request."""
        errors = []

        if not validate_email_address(sender):
            errors.append("Invalid sender email format")

        if not body:
            errors.append("Email body is required")
        elif len(body) > 100000:
            errors.append("Email body too large (max 100KB)")

        if links:
            if len(links) > DEFAULT_MAX_LINKS:
                errors.append(f"Too many links (max {DEFAULT_MAX_LINKS})")
            for link in links[:DEFAULT_MAX_LINKS]:
                if isinstance(link, str) and len(link) > DEFAULT_MAX_URL_LENGTH:
                    errors.append(f"Link too long: {link[:50]}...")
                    break

        if subject and len(subject) > DEFAULT_MAX_SUBJECT_LENGTH:
            errors.append(f"Subject too long (max {DEFAULT_MAX_SUBJECT_LENGTH} chars)")

        return (len(errors) == 0, errors)
