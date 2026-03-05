from security.middleware import validate_url


def test_validate_url_valid():
    """Test valid URLs that should be accepted."""
    valid_urls = [
        "http://example.com",
        "https://example.com",
        "https://example.com/path/to/resource",
        "http://example.com?query=123",
        "https://example.com#fragment",
        "https://sub.domain.example.com",
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "https://user:pass@example.com",
        "http://[::1]",  # IPv6
    ]
    for url in valid_urls:
        assert validate_url(url) is True, f"Expected {url} to be valid"


def test_validate_url_invalid_schemes():
    """Test URLs with invalid schemes that should be rejected."""
    invalid_urls = [
        "javascript:alert(1)",
        "data:text/html,<html>",
        "ftp://example.com",
        "file:///etc/passwd",
        "ws://example.com",
        "gopher://example.com",
        "mailto:test@example.com",
        "vnc://example.com",
        "telnet://example.com",
        "not-a-url",
        "http://",
        "",
    ]
    for url in invalid_urls:
        assert validate_url(url) is False, f"Expected {url} to be invalid"


def test_validate_url_malicious_bypasses():
    """Test URLs attempting to bypass validation using control characters or structure anomalies."""
    malicious_urls = [
        "http://example.com\r\n/path",  # CRLF injection
        "http://example.com#\r\nscript:",
        " javascript:alert(1)",  # Leading space
        "http://foo.bar?q=Spaces Here",  # Space in query (should be URL encoded)
        "http://\x01\x02",  # Control characters
        "http://example.com/\x00/path",  # Null byte
        "https://example.com\t/path",  # Tab character
        "http://example.com/path\n",  # Trailing newline
    ]
    for url in malicious_urls:
        assert validate_url(url) is False, f"Expected {url!r} to be invalid"


def test_validate_url_missing_components():
    """Test URLs missing critical components like netloc or hostname."""
    missing_component_urls = [
        "http:/example.com",  # Missing a slash
        "http:///",  # Missing netloc
        "https://?",  # Missing netloc
        "http://#",  # Missing netloc
    ]
    for url in missing_component_urls:
        assert validate_url(url) is False, f"Expected {url} to be invalid"


def test_validate_url_too_long():
    """Test URLs that exceed the maximum length limit."""
    long_url = "http://example.com/" + ("a" * 2048)
    assert validate_url(long_url) is False, "Expected overly long URL to be invalid"
