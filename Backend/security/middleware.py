"""
Security Middleware and Utilities for ZeroPhish
Implements input validation, sanitization, and security headers
"""

import html
import re
import urllib.parse
from typing import Optional

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from email_validator import validate_email, EmailNotValidError


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Note: X-XSS-Protection is largely legacy but kept for older browsers
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
    """Limit request body size to prevent DoS attacks."""

    def __init__(self, app, max_size: int = 1_000_000):  # 1MB default
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next):
        # Check content length
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_size:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})

        return await call_next(request)


def sanitize_email_content(text: str, max_length: int = 50000) -> str:
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
    if not email or len(email) > 320:  # RFC 5321
        return False
    
    try:
        # check_deliverability=False avoids performing a DNS lookup during validation
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def validate_url(url: str) -> bool:
    """Validate URL format and prevent CRLF/Injection."""
    if not url or len(url) > 2048:
        return False

    if re.search(r"[\s\x00-\x1F\x7F]", url):
        return False

    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False

        if not parsed.netloc or not parsed.hostname:
            return False

        return True
    except ValueError:
        return False


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
        elif len(body) > 100000:
            errors.append("Email body too large (max 100KB)")

        if links:
            if len(links) > 100:
                errors.append("Too many links (max 100)")
            for link in links[:100]:
                if isinstance(link, str) and len(link) > 2048:
                    errors.append(f"Link too long: {link[:50]}...")
                    break

        if subject and len(subject) > 1000:
            errors.append("Subject too long (max 1000 chars)")

        return {"valid": len(errors) == 0, "errors": errors}