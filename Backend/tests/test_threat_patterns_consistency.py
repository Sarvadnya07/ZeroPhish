"""
Consistency tests between centralized threat configuration and backend threat engines.
Ensures threat intelligence rules never drift silently.
"""

import json
from pathlib import Path

import pytest

from tier_2.rules import (
    AUTHORITY_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_PATTERNS,
    SCARE_TACTICS,
    SUSPICIOUS_URLS,
    TOP_50_SPOOFED,
    URGENCY_PATTERNS,
    URL_SHORTENERS,
    levenshtein,
)


def test_threat_patterns_json_exists_and_valid():
    """Verify master configuration JSON file is valid and non-empty."""
    config_path = Path(__file__).resolve().parents[2] / "config" / "threat_patterns.json"
    assert config_path.is_file(), f"Master config not found at {config_path}"

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "URGENCY_PATTERNS" in data
    assert "FINANCIAL_PATTERNS" in data
    assert "CREDENTIAL_PATTERNS" in data
    assert "AUTHORITY_PATTERNS" in data
    assert "SCARE_TACTICS" in data
    assert "SUSPICIOUS_URLS" in data
    assert "TOP_50_SPOOFED" in data
    assert "URL_SHORTENERS" in data


def test_rules_loaded_from_config():
    """Ensure rules loaded into tier_2.rules contain expected baseline patterns."""
    assert "urgent" in URGENCY_PATTERNS
    assert "password" in CREDENTIAL_PATTERNS
    assert "bank" in FINANCIAL_PATTERNS
    assert "irs" in AUTHORITY_PATTERNS
    assert "suspend" in SCARE_TACTICS
    assert any(u == "bit.ly" for u in SUSPICIOUS_URLS)
    assert any(s == "paypal.com" for s in TOP_50_SPOOFED)
    assert any(q == "tinyurl.com" for q in URL_SHORTENERS)


def test_levenshtein_distance_correctness():
    """Verify Levenshtein distance calculations."""
    assert levenshtein("paypal.com", "paypal.com") == 0
    assert levenshtein("paypa1.com", "paypal.com") == 1
    assert levenshtein("paypa1.co", "paypal.com") == 2
    assert levenshtein("", "abc") == 3
    assert levenshtein("abc", "") == 3
    assert levenshtein("", "") == 0
