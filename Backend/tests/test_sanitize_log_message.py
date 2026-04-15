import sys
from unittest.mock import MagicMock

# Mock dependencies required by security.middleware
sys.modules['fastapi'] = MagicMock()
sys.modules['fastapi.responses'] = MagicMock()
sys.modules['starlette'] = MagicMock()
sys.modules['starlette.middleware'] = MagicMock()
sys.modules['starlette.middleware.base'] = MagicMock()
sys.modules['email_validator'] = MagicMock()

from security.middleware import sanitize_log_message


def test_sanitize_log_message_empty():
    """Test that an empty string returns an empty string."""
    assert sanitize_log_message("") == ""
    assert sanitize_log_message(None) == ""


def test_sanitize_log_message_short_no_newlines():
    """Test that a short string without newlines is returned unmodified."""
    msg = "This is a normal log message."
    assert sanitize_log_message(msg) == msg


def test_sanitize_log_message_with_newlines():
    """Test that newlines and carriage returns are replaced with spaces."""
    msg = "This has\na newline and\ra carriage return."
    expected = "This has a newline and a carriage return."
    assert sanitize_log_message(msg) == expected


def test_sanitize_log_message_exactly_500_chars():
    """Test that a message of exactly 500 characters is not truncated."""
    msg = "a" * 500
    assert sanitize_log_message(msg) == msg


def test_sanitize_log_message_over_500_chars():
    """Test that a message over 500 characters is truncated to 497 chars plus '...'."""
    msg = "a" * 501
    expected = ("a" * 497) + "..."
    assert sanitize_log_message(msg) == expected
