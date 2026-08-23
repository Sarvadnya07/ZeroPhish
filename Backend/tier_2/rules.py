"""
ZeroPhish Tier 2 Threat Rules & Pattern Matching Constants.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


def load_threat_patterns() -> Dict[str, List[str]]:
    """Load threat patterns from canonical JSON file with multiple search paths."""
    candidates = [
        Path(__file__).resolve().parent / "threat_patterns.json",
        Path(__file__).resolve().parents[2] / "config" / "threat_patterns.json",
        Path(__file__).resolve().parent.parent / "config" / "threat_patterns.json",
    ]
    for path in candidates:
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to load threat patterns from %s: %s", path, e)
    return {}


_PATTERNS = load_threat_patterns()

URGENCY_PATTERNS: List[str] = _PATTERNS.get("URGENCY_PATTERNS", [])
FINANCIAL_PATTERNS: List[str] = _PATTERNS.get("FINANCIAL_PATTERNS", [])
CREDENTIAL_PATTERNS: List[str] = _PATTERNS.get("CREDENTIAL_PATTERNS", [])
AUTHORITY_PATTERNS: List[str] = _PATTERNS.get("AUTHORITY_PATTERNS", [])
SCARE_TACTICS: List[str] = _PATTERNS.get("SCARE_TACTICS", [])
SUSPICIOUS_URLS: List[str] = _PATTERNS.get("SUSPICIOUS_URLS", [])

# Pre-compiled regular expressions
URGENCY_RE = re.compile(
    "|".join(map(re.escape, sorted(URGENCY_PATTERNS, key=len, reverse=True))) if URGENCY_PATTERNS else "$^"
)
FINANCIAL_RE = re.compile(
    "|".join(map(re.escape, sorted(FINANCIAL_PATTERNS, key=len, reverse=True))) if FINANCIAL_PATTERNS else "$^"
)
CREDENTIAL_RE = re.compile(
    "|".join(map(re.escape, sorted(CREDENTIAL_PATTERNS, key=len, reverse=True))) if CREDENTIAL_PATTERNS else "$^"
)
AUTHORITY_RE = re.compile(
    "|".join(map(re.escape, sorted(AUTHORITY_PATTERNS, key=len, reverse=True))) if AUTHORITY_PATTERNS else "$^"
)
SCARE_RE = re.compile(
    "|".join(map(re.escape, sorted(SCARE_TACTICS, key=len, reverse=True))) if SCARE_TACTICS else "$^"
)
SUSPICIOUS_URLS_RE = re.compile(
    "|".join(map(re.escape, sorted(SUSPICIOUS_URLS, key=len, reverse=True))) if SUSPICIOUS_URLS else "$^"
)

IP_LINK_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)")
SUSPICIOUS_TLD_REGEX = re.compile(
    r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)"
)

TOP_50_SPOOFED: Set[str] = set(
    _PATTERNS.get(
        "TOP_50_SPOOFED",
        [
            "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com", "netflix.com",
            "facebook.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "github.com",
            "linkedin.com", "dropbox.com", "docusign.com", "adobe.com", "instagram.com",
            "yahoo.com", "outlook.com", "office.com", "live.com", "amazonaws.com",
            "twitter.com", "x.com", "salesforce.com", "slack.com", "zoom.us", "citi.com",
        ],
    )
)

URL_SHORTENERS: Set[str] = set(
    _PATTERNS.get(
        "URL_SHORTENERS",
        [
            "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
        ],
    )
)


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]
