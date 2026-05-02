import pytest
from main import _category_from_verdict, _verdict_from_score

# --- Tests for _category_from_verdict ---

def test_category_from_verdict_critical():
    """Test CRITICAL verdict maps to phishing."""
    assert _category_from_verdict("CRITICAL") == "phishing"
    assert _category_from_verdict("critical") == "phishing"
    assert _category_from_verdict("  CriTiCal  ") == "phishing"

def test_category_from_verdict_suspicious():
    """Test SUSPICIOUS verdict maps to spam."""
    assert _category_from_verdict("SUSPICIOUS") == "spam"
    assert _category_from_verdict("suspicious") == "spam"
    assert _category_from_verdict("  SusPicious  ") == "spam"

def test_category_from_verdict_safe():
    """Test other known safe verdicts map to safe."""
    assert _category_from_verdict("OK") == "safe"
    assert _category_from_verdict("ok") == "safe"
    assert _category_from_verdict(" SAFE ") == "safe"

def test_category_from_verdict_unknown():
    """Test unknown verdicts map to safe."""
    assert _category_from_verdict("unknown") == "safe"
    assert _category_from_verdict("random_string") == "safe"

def test_category_from_verdict_empty_or_none():
    """Test None and empty strings map to safe."""
    assert _category_from_verdict(None) == "safe"
    assert _category_from_verdict("") == "safe"
    assert _category_from_verdict("   ") == "safe"


# --- Tests for _verdict_from_score ---

def test_verdict_from_score_critical():
    """Boundary and above (70+)"""
    assert _verdict_from_score(70) == "CRITICAL"
    assert _verdict_from_score(71) == "CRITICAL"
    assert _verdict_from_score(100) == "CRITICAL"
    assert _verdict_from_score(999) == "CRITICAL"

def test_verdict_from_score_suspicious():
    """Boundary and between safe and critical (30-69)"""
    assert _verdict_from_score(30) == "SUSPICIOUS"
    assert _verdict_from_score(31) == "SUSPICIOUS"
    assert _verdict_from_score(69) == "SUSPICIOUS"

def test_verdict_from_score_safe():
    """Boundary and below (0-29)"""
    assert _verdict_from_score(29) == "SAFE"
    assert _verdict_from_score(0) == "SAFE"
    assert _verdict_from_score(-10) == "SAFE"