"""
Security Middleware and Utilities for ZeroPhish
Implements input validation, sanitization, and security headers
"""

import re
from typing import Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import html


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'; object-src 'none'"
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
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"}
            )
        
        return await call_next(request)


def sanitize_email_content(text: str, max_length: int = 50000) -> str:
    """
    Sanitize email content to prevent XSS and injection attacks.
    
    Args:
        text: Raw email content
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Truncate to max length
    text = text[:max_length]
    
    # HTML escape to prevent XSS
    text = html.escape(text)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text


def validate_email_address(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not email or len(email) > 320:  # RFC 5321
        return False
    
    # Basic email regex (not perfect but good enough)
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not url or len(url) > 2048:  # Common max URL length
        return False
    
    # Basic URL validation
    pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
    return bool(re.match(pattern, url))


def sanitize_log_message(message: str) -> str:
    """
    Sanitize log messages to prevent log injection.
    
    Args:
        message: Log message
        
    Returns:
        Sanitized message
    """
    if not message:
        return ""
    
    # Remove newlines and carriage returns to prevent log injection
    message = message.replace('\n', ' ').replace('\r', ' ')
    
    # Truncate long messages
    if len(message) > 500:
        message = message[:497] + "..."
    
    return message


def get_generic_error_message(status_code: int) -> str:
    """
    Get generic error message for client (hide internal details).
    
    Args:
        status_code: HTTP status code
        
    Returns:
        Generic error message
    """
    error_messages = {
        400: "Invalid request",
        401: "Authentication required",
        403: "Access denied",
        404: "Resource not found",
        413: "Request too large",
        429: "Too many requests",
        500: "Internal server error",
        503: "Service temporarily unavailable"
    }
    
    return error_messages.get(status_code, "An error occurred")


class InputValidator:
    """Validate and sanitize request inputs."""
    
    @staticmethod
    def validate_scan_request(sender: str, body: str, links: list, subject: Optional[str] = None) -> dict:
        """
        Validate scan request inputs.
        
        Returns:
            dict with 'valid' bool and 'errors' list
        """
        errors = []
        
        # Validate sender email
        if not validate_email_address(sender):
            errors.append("Invalid sender email format")
        
        # Validate body length
        if not body:
            errors.append("Email body is required")
        elif len(body) > 100000:  # 100KB max
            errors.append("Email body too large (max 100KB)")
        
        # Validate links
        if links:
            if len(links) > 100:  # Max 100 links
                errors.append("Too many links (max 100)")
            
            for link in links[:100]:  # Validate first 100
                if isinstance(link, str):
                    if len(link) > 2048:
                        errors.append(f"Link too long: {link[:50]}...")
                        break
        
        # Validate subject
        if subject and len(subject) > 1000:
            errors.append("Subject too long (max 1000 chars)")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
