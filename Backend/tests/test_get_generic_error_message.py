import pytest
from security.middleware import get_generic_error_message

@pytest.mark.parametrize(
    "status_code, expected_message",
    [
        (400, "Invalid request"),
        (401, "Authentication required"),
        (403, "Access denied"),
        (404, "Resource not found"),
        (413, "Request too large"),
        (429, "Too many requests"),
        (500, "Internal server error"),
        (503, "Service temporarily unavailable"),
    ],
)
def test_get_generic_error_message_mapped_codes(status_code, expected_message):
    """Test that mapped status codes return their specific error messages."""
    assert get_generic_error_message(status_code) == expected_message

@pytest.mark.parametrize(
    "status_code",
    [
        200,
        201,
        301,
        302,
        418,
        502,
        999,
        -1,
        0,
    ],
)
def test_get_generic_error_message_unmapped_codes(status_code):
    """Test that unmapped status codes return the default error message."""
    assert get_generic_error_message(status_code) == "An error occurred"

def test_get_generic_error_message_invalid_type():
    """Test that invalid types (if they ever get passed) handle gracefully by returning the default error message."""
    assert get_generic_error_message("400") == "An error occurred"
    assert get_generic_error_message(None) == "An error occurred"
