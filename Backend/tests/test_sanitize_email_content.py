from security.middleware import sanitize_email_content


def test_sanitize_email_content_empty_and_none():
    """Test empty strings and None input."""
    assert sanitize_email_content("") == ""
    assert sanitize_email_content(None) == ""


def test_sanitize_email_content_basic_string():
    """Test basic string without special characters."""
    assert sanitize_email_content("Hello World") == "Hello World"


def test_sanitize_email_content_html_escaping():
    """Test string with HTML tags to ensure escaping works properly."""
    html_str = "<script>alert('xss');</script>"
    # html.escape escapes < to &lt;, > to &gt;, & to &amp;, " to &quot;, ' to &#x27;
    expected = "&lt;script&gt;alert(&#x27;xss&#x27;);&lt;/script&gt;"
    assert sanitize_email_content(html_str) == expected

    html_str_double = '<a href="test">link</a>'
    expected_double = "&lt;a href=&quot;test&quot;&gt;link&lt;/a&gt;"
    assert sanitize_email_content(html_str_double) == expected_double


def test_sanitize_email_content_null_bytes():
    """Test string containing null bytes."""
    null_str = "hello\x00world\x00"
    assert sanitize_email_content(null_str) == "helloworld"


def test_sanitize_email_content_truncation():
    """Test that the string is correctly truncated to max_length."""
    # Default max_length is 50000
    long_str = "a" * 50005
    assert sanitize_email_content(long_str) == "a" * 50000

    # Custom max_length
    custom_str = "abcdefghij"
    assert sanitize_email_content(custom_str, max_length=5) == "abcde"


def test_sanitize_email_content_combination_edge_cases():
    """Test a combination of HTML escaping, null bytes, and truncation."""
    # Length of "a" * 10 is 10.
    # Total input string length is > 15
    combo_str = "<a>\x00" + ("b" * 20)
    # Truncating to 10 will keep "<a>\x00bbbbbb" (length 10)
    # Then escapes <a> -> &lt;a&gt; (length 12)
    # Removes \x00 (length 11) -> "&lt;a&gt;bbbbbb"
    result = sanitize_email_content(combo_str, max_length=10)
    assert result == "&lt;a&gt;bbbbbb"
