"""
Tier 2 Analysis Module — Metadata, Domain Intel, OSINT & Threat Pattern Heuristics.
"""

from __future__ import annotations

from .analyzer import ThreatAnalysis, ThreatAnalyzer
from .domain_intel import analyze_domain_age, get_domain_age
from .rules import (
    AUTHORITY_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_PATTERNS,
    IP_LINK_REGEX,
    SCARE_TACTICS,
    SUSPICIOUS_TLD_REGEX,
    SUSPICIOUS_URLS,
    TOP_50_SPOOFED,
    URGENCY_PATTERNS,
    URL_SHORTENERS,
    levenshtein,
)

__all__ = [
    "ThreatAnalyzer",
    "ThreatAnalysis",
    "analyze_domain_age",
    "get_domain_age",
    "levenshtein",
    "TOP_50_SPOOFED",
    "URL_SHORTENERS",
    "SUSPICIOUS_TLD_REGEX",
    "IP_LINK_REGEX",
    "URGENCY_PATTERNS",
    "FINANCIAL_PATTERNS",
    "CREDENTIAL_PATTERNS",
    "AUTHORITY_PATTERNS",
    "SCARE_TACTICS",
    "SUSPICIOUS_URLS",
]
