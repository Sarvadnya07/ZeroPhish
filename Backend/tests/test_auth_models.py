import pytest
from auth.models import hash_password, verify_password

def test_hash_password_format():
    password = "MySecurePassword123!"
    hashed = hash_password(password)

    parts = hashed.split("$")
    assert len(parts) == 3
    assert parts[0] == "pbkdf2_sha256"
    assert len(parts[1]) == 32  # 16 bytes hex = 32 chars
    assert len(parts[2]) == 64  # 32 bytes hex = 64 chars

def test_hash_password_randomness():
    password = "SamePassword"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2  # Salt should be different

def test_verify_password_correct():
    password = "MySecurePassword123!"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True

def test_verify_password_incorrect():
    password = "MySecurePassword123!"
    hashed = hash_password(password)

    assert verify_password("WrongPassword!", hashed) is False

def test_verify_password_invalid_hash_format():
    password = "MySecurePassword123!"
    # Malformed hashes
    assert verify_password(password, "invalid_hash_format") is False
    assert verify_password(password, "pbkdf2_sha256$tooshort") is False
    assert verify_password(password, "$$") is False
    assert verify_password(password, None) is False
