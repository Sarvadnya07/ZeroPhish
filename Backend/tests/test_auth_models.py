import pytest
from auth.models import hash_password, verify_password

def test_hash_password_format():
    password = "my_secure_password"
    hashed = hash_password(password)
    parts = hashed.split("$")
    assert len(parts) == 3
    assert parts[0] == "pbkdf2_sha256"
    assert len(parts[1]) > 0
    assert len(parts[2]) > 0

def test_verify_password_success():
    password = "my_secure_password"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True

def test_verify_password_failure():
    password = "my_secure_password"
    wrong_password = "wrong_password"
    hashed = hash_password(password)
    assert verify_password(wrong_password, hashed) is False

def test_verify_password_malformed_hash():
    password = "my_secure_password"
    # Missing parts
    assert verify_password(password, "malformed_hash") is False
    # Missing parts, but has one $
    assert verify_password(password, "malformed$hash") is False
    # Too many parts
    assert verify_password(password, "too$many$parts$in$hash") is False

def test_verify_password_invalid_types():
    password = "my_secure_password"
    # Pass None as hash
    assert verify_password(password, None) is False # type: ignore
    # Pass int as hash
    assert verify_password(password, 12345) is False # type: ignore
    # Pass None as password
    hashed = hash_password(password)
    assert verify_password(None, hashed) is False # type: ignore
