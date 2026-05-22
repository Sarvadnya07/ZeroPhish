import pytest
from security.middleware import validate_email_address

@pytest.mark.parametrize(
    "email, expected",
    [
        # Valid cases
        ("test@example.com", True),
        ("user.name+tag+sorting@example.com", True),
        ("x@example.com", True),
        ("example-indeed@strange-example.com", True),
        ("example@s.example", True),
        ("a" * 64 + "@example.com", True), # Local part up to 64 chars

        # Invalid cases
        ("", False),
        (None, False),
        ("testexample.com", False),
        ("test@", False),
        ("@example.com", False),
        ("test@.com", False),
        ("test@example..com", False),
        ("test@example.com ", False), # Trailing space
        (" test@example.com", False), # Leading space
        ("test @example.com", False), # Space in local part
        ("test@ example.com", False), # Space in domain
        ("test@example_domain.com", False), # Underscore in domain (standard validator doesn't like this usually for domains, though allowed in hostnames technically sometimes, email-validator usually rejects)
        ("a" * 65 + "@example.com", False), # Local part too long (RFC limits to 64)
        ("test@" + "a" * 256 + ".com", False), # Domain too long
        ("a" * 321 + "@example.com", False), # Overall string > 320 check

        # ReDoS-like and complex invalid cases
        ("a" * 100 + "@" + "b" * 100 + ".com", False), # Local part > 64 chars
        ("test@example.com<script>alert(1)</script>", False),
    ]
)
def test_validate_email_address(email, expected):
    assert validate_email_address(email) is expected
