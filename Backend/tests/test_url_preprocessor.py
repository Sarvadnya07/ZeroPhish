"""
Unit tests for Backend/ml/url_preprocessor.py.
Tests safe normalization, length bounding, and feature extraction across edge-case URLs.
"""

import pytest

from ml.url_preprocessor import MAX_URL_LENGTH, URLPreprocessor


def test_preprocess_standard_urls():
    assert URLPreprocessor.preprocess("https://example.com/login") == "https://example.com/login"
    assert (
        URLPreprocessor.preprocess("http://example.com:8080/path") == "http://example.com:8080/path"
    )
    # Adds default protocol if missing
    assert URLPreprocessor.preprocess("example.com/test") == "http://example.com/test"
    assert URLPreprocessor.preprocess("//cdn.example.com/lib.js") == "http://cdn.example.com/lib.js"


def test_preprocess_strips_control_chars():
    dirty = "  https://example.com/login\r\n\t\x00  "
    cleaned = URLPreprocessor.preprocess(dirty)
    assert cleaned == "https://example.com/login"


def test_preprocess_bounds_overlong_input():
    overlong = "https://example.com/" + "a" * (MAX_URL_LENGTH + 500)
    cleaned = URLPreprocessor.preprocess(overlong)
    assert len(cleaned) == MAX_URL_LENGTH


def test_preprocess_empty_and_invalid_inputs():
    assert URLPreprocessor.preprocess("") == ""
    assert URLPreprocessor.preprocess("   ") == ""
    assert URLPreprocessor.preprocess(None) == ""


def test_extract_features_ip_and_port():
    features = URLPreprocessor.extract_features("http://192.168.1.1:8080/admin")
    assert features["valid"] is True
    assert features["is_ip"] is True
    assert features["has_port"] is True
    assert features["domain"] == "192.168.1.1"


def test_extract_features_punycode():
    features = URLPreprocessor.extract_features("http://xn--pypal-4ve.com/signin")
    assert features["valid"] is True
    assert features["is_punycode"] is True
    assert features["domain"] == "xn--pypal-4ve.com"


def test_extract_features_userinfo():
    features = URLPreprocessor.extract_features("http://trusted.com@evil.com/path")
    assert features["valid"] is True
    assert features["has_userinfo"] is True
    assert features["domain"] == "evil.com"


def test_extract_features_empty_url():
    features = URLPreprocessor.extract_features("")
    assert features["valid"] is False
    assert features["length"] == 0
