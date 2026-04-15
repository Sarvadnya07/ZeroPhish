import pytest
from main import _category_from_verdict

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
