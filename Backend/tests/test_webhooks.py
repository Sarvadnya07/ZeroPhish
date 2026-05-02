import pytest
from webhooks.service import _sign
import hmac
import hashlib

def test_sign_with_known_inputs():
    """Test HMAC-SHA256 generation with a known secret and payload."""
    secret = "my_secret"
    payload = b"my_payload"
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    result = _sign(secret, payload)

    assert result == expected
    assert result == "sha256=91bab3317e295fea7d87d0132c73fc88f750d3d83a48aae5d78959eaeadd0402"

def test_sign_with_empty_payload():
    """Test HMAC-SHA256 generation with an empty payload."""
    secret = "my_secret"
    payload = b""
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    result = _sign(secret, payload)

    assert result == expected

def test_sign_with_empty_secret():
    """Test HMAC-SHA256 generation with an empty secret."""
    secret = ""
    payload = b"my_payload"
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    result = _sign(secret, payload)

    assert result == expected

def test_sign_with_empty_secret_and_payload():
    """Test HMAC-SHA256 generation with an empty secret and an empty payload."""
    secret = ""
    payload = b""
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    result = _sign(secret, payload)

    assert result == expected
