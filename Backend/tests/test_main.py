import pytest

from main import _verdict_from_score


def test_verdict_from_score_critical():
    # Boundary and above
    assert _verdict_from_score(70) == "CRITICAL"
    assert _verdict_from_score(71) == "CRITICAL"
    assert _verdict_from_score(100) == "CRITICAL"
    assert _verdict_from_score(999) == "CRITICAL"

def test_verdict_from_score_suspicious():
    # Boundary and between safe and critical
    assert _verdict_from_score(30) == "SUSPICIOUS"
    assert _verdict_from_score(31) == "SUSPICIOUS"
    assert _verdict_from_score(69) == "SUSPICIOUS"

def test_verdict_from_score_safe():
    # Boundary and below
    assert _verdict_from_score(29) == "SAFE"
    assert _verdict_from_score(0) == "SAFE"
    assert _verdict_from_score(-10) == "SAFE"
