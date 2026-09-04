"""
Security Middleware and Utilities for ZeroPhish

Implements input validation, sanitization, and security headers.
Provides middleware for security headers, request size limiting, and SSRF protection.
"""

from __future__ import annotations

import html
import ipaddress
import logging
import re
import socket
import urllib.parse
from typing import Optional

from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from security.audit_logger import log_ssrf_blocked

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MAX_SIZE = 1_000_000  # 1 MB
MAX_EMAIL_LENGTH = 320  # RFC 5321
MAX_URL_LENGTH = 2048
MAX_LINKS_PER_REQUEST = 100
MAX_BODY_LENGTH = 100_000  # 100 KB
DEFAULT_MAX_BODY_LENGTH = 50_000  # 50 KB default sanitization truncation

# Dangerous schemes
DANGEROUS_SCHEMES = {"javascript:", "data:", "file:", "ftp:", "gopher:", "telnet:", "ws:", "wss:"}

# Reserved subnets for SSRF protection
RESERVED_SUBNETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    """

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
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Remove server header (information disclosure)
        if "server" in response.headers:
            del response.headers["server"]

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Limit request body size to prevent DoS attacks.
    """

    def __init__(self, app, max_size: int = DEFAULT_MAX_SIZE):
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_size:
                    logger.warning("Request size exceeded: %s > %s", content_length, self.max_size)
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request body too large"},
                    )
            except ValueError:
                pass

        return await call_next(request)


# ---------- Validation Functions ----------
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
    """
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def validate_url(url: str) -> bool:
    """Validate URL format and prevent CRLF/Injection and dangerous schemes."""
    if not url or len(url) > MAX_URL_LENGTH:
        return False

    if re.search(r"[\s\x00-\x1F\x7F]", url):
        return False

    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False
        if not parsed.netloc or not parsed.hostname:
            return False
        return True
    except ValueError:
        return False


def is_safe_webhook_url(url: str, allow_http: bool = False) -> bool:
    """
    Validate destination URL to prevent SSRF attacks against:
    - Loopback addresses (127.0.0.0/8, ::1)
    - Private RFC1918 networks
    - Link-local & cloud metadata (169.254.0.0/16, fe80::/10)
    - Carrier-grade NAT (100.64.0.0/10)
    - Multicast, reserved, unspecified addresses
    - IPv4-mapped IPv6 representations
    - Embedded user credentials
    """
    if not validate_url(url):
        return False

    parsed = urllib.parse.urlparse(url)
    if parsed.username or parsed.password:
        return False

    scheme = parsed.scheme.lower()
    if scheme == "http" and not allow_http:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Block well-known localhost aliases early
    lower_host = hostname.lower()
    if lower_host in ("localhost", "localhost.localdomain", "127.0.0.1", "0.0.0.0", "::1"):
        log_ssrf_blocked(hostname, "localhost_alias")
        return False

    try:
        # Resolve hostname to all IP addresses
        ip_objs = []
        try:
            ip_objs.append(ipaddress.ip_address(hostname))
        except ValueError:
            # Check if hostname can be parsed as alternate numeric IP (decimal, hex, octal via inet_aton)
            try:
                raw_bytes = socket.inet_aton(hostname)
                ip_objs.append(ipaddress.IPv4Address(raw_bytes))
            except (OSError, ValueError):
                pass

            # DNS resolution - use getaddrinfo if not already resolved
            if not ip_objs:
                try:
                    addrinfo = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
                    for res in addrinfo:
                        sockaddr = res[4]
                        ip_objs.append(ipaddress.ip_address(sockaddr[0]))
                except socket.gaierror:
                    return False

        if not ip_objs:
            return False

        # Check each resolved IP against reserved subnets
        for ip in ip_objs:
            # Handle IPv4-mapped IPv6 addresses
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            # Handle RFC 6052 Well-Known Prefix NAT64 addresses (64:ff9b::/96)
            elif isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("64:ff9b::/96"):
                ip = ipaddress.IPv4Address(ip.packed[-4:])

            for subnet in RESERVED_SUBNETS:
                if ip in subnet:
                    log_ssrf_blocked(str(ip), f"reserved_subnet: {subnet}")
                    return False

        return True
    except Exception as e:
        logger.warning("SSRF check failed for %s: %s", hostname, e)
        return False


def is_safe_url(url: str, allow_http: bool = False) -> bool:
    """Alias for is_safe_webhook_url for general SSRF checks."""
    return is_safe_webhook_url(url, allow_http=allow_http)


def sanitize_log_message(message: str) -> str:
    """Sanitize log messages to prevent log injection."""
    if not message:
        return ""
    message = message.replace("\n", " ").replace("\r", " ")
    if len(message) > 500:
        message = message[:497] + "..."
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
    """Validate and sanitize request inputs."""

    @staticmethod
    def validate_scan_request(
        sender: str, body: str, links: list, subject: Optional[str] = None
    ) -> dict:
        errors = []

        if not validate_email_address(sender):
            errors.append("Invalid sender email format")

        if not body:
            errors.append("Email body is required")
        elif len(body) > MAX_BODY_LENGTH:
            errors.append(f"Email body too large (max {MAX_BODY_LENGTH} chars)")

        if links:
            if len(links) > MAX_LINKS_PER_REQUEST:
                errors.append(f"Too many links (max {MAX_LINKS_PER_REQUEST})")
            for link in links[:MAX_LINKS_PER_REQUEST]:
                if isinstance(link, str) and len(link) > MAX_URL_LENGTH:
                    errors.append(f"Link too long: {link[:50]}...")
                    break
                # Also validate each link
                if not validate_url(link):
                    errors.append("Invalid URL format in links")

        if subject and len(subject) > 500:
            errors.append("Subject too long (max 500 chars)")

        return {"valid": len(errors) == 0, "errors": errors}