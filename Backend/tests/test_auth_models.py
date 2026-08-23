import pytest

from auth.models import hash_password, verify_password


def test_hash_password_format():
    """Verify hash uses PBKDF2 with correct separator and length."""
    password = "MySecurePassword123!"
    hashed = hash_password(password)

    parts = hashed.split("$")
    assert len(parts) == 3
    assert parts[0] == "pbkdf2_sha256"
    # Main branch assertions: exact length checks for salt (32) and hash (64)
    assert len(parts[1]) == 32
    assert len(parts[2]) == 64


def test_hash_password_randomness():
    """Ensure different salts are used for the same password."""
    password = "SamePassword"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2


def test_verify_password_success():
    """Confirm correct password matches the hash."""
    password = "MySecurePassword123!"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True


def test_verify_password_failure():
    """Confirm incorrect password does not match."""
    password = "MySecurePassword123!"
    hashed = hash_password(password)
    assert verify_password("wrong_password", hashed) is False


def test_verify_password_malformed_hash():
    """Test various corrupted hash formats."""
    password = "MySecurePassword123!"
    # Combined edge cases from both branches
    assert verify_password(password, "malformed_hash") is False
    assert verify_password(password, "pbkdf2_sha256$tooshort") is False
    assert verify_password(password, "too$many$parts$in$hash") is False
    assert verify_password(password, "$$") is False


def test_verify_password_invalid_types():
    """Test behavior when passing non-string types."""
    password = "MySecurePassword123!"
    hashed = hash_password(password)

    # None handling
    assert verify_password(password, None) is False  # type: ignore
    assert verify_password(None, hashed) is False  # type: ignore

    # Numeric types
    assert verify_password(password, 12345) is False  # type: ignore
