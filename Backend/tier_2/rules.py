"""
ZeroPhish Tier 2 Threat Rules & Pattern Matching Constants.

This module loads threat patterns from a canonical JSON file and compiles
regular expressions for efficient pattern matching. It provides fallback
patterns if the file is missing, and supports dynamic reloading.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ---------- Configuration ----------
PATTERN_FILE_CANDIDATES = [
    Path(__file__).resolve().parent / "threat_patterns.json",
    Path(__file__).resolve().parents[2] / "config" / "threat_patterns.json",
    Path(__file__).resolve().parent.parent / "config" / "threat_patterns.json",
]

# Fallback patterns (used if file loading fails)
_FALLBACK_PATTERNS = {
    "URGENCY_PATTERNS": [
        "urgent", "immediate", "as soon as possible", "act now", "expires today",
        "limited time", "don't delay", "last chance", "critical", "emergency",
    ],
    "FINANCIAL_PATTERNS": [
        "invoice", "payment", "refund", "transfer", "wire", "credit card",
        "bank account", "financial", "tax refund", "bonus", "salary",
    ],
    "CREDENTIAL_PATTERNS": [
        "password", "username", "login", "sign in", "verify account",
        "reset password", "account locked", "unauthorized access", "security alert",
    ],
    "AUTHORITY_PATTERNS": [
        "administrator", "security team", "help desk", "support", "it department",
        "ceo", "president", "director", "manager", "supervisor",
    ],
    "SCARE_TACTICS": [
        "suspended", "terminated", "deactivated", "locked", "blocked",
        "violation", "legal action", "lawsuit", "compliance", "investigation",
    ],
    "SUSPICIOUS_URLS": [
        "login", "verify", "update", "secure", "authenticate", "confirm",
        "validate", "reset", "unlock", "restore", "activate",
    ],
    "TOP_50_SPOOFED": [
        "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
        "netflix.com", "facebook.com", "chase.com", "wellsfargo.com",
        "bankofamerica.com", "github.com", "linkedin.com", "dropbox.com",
        "docusign.com", "adobe.com", "instagram.com", "yahoo.com", "outlook.com",
        "office.com", "live.com", "amazonaws.com", "twitter.com", "x.com",
        "salesforce.com", "slack.com", "zoom.us", "citi.com",
    ],
    "URL_SHORTENERS": [
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    ],
}


def load_threat_patterns() -> Dict[str, List[str]]:
    """
    Load threat patterns from the canonical JSON file.

    Searches multiple paths and returns the first valid file found.
    If no file is found or parsing fails, returns fallback patterns.

    Returns:
        Dict mapping pattern category names to lists of pattern strings.
    """
    for path in PATTERN_FILE_CANDIDATES:
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # Validate that all values are lists of strings
                for key, value in data.items():
                    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                        logger.warning("Pattern category '%s' has invalid format, skipping", key)
                        continue
                logger.info("Loaded threat patterns from %s (%d categories)", path, len(data))
                return data
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON from %s: %s", path, e)
            except Exception as e:
                logger.error("Failed to load threat patterns from %s: %s", path, e)

    logger.warning("No valid threat patterns file found, using fallback patterns.")
    return _FALLBACK_PATTERNS


# ---------- Load Patterns ----------
_PATTERNS = load_threat_patterns()

# Expose pattern categories
URGENCY_PATTERNS: List[str] = _PATTERNS.get("URGENCY_PATTERNS", [])
FINANCIAL_PATTERNS: List[str] = _PATTERNS.get("FINANCIAL_PATTERNS", [])
CREDENTIAL_PATTERNS: List[str] = _PATTERNS.get("CREDENTIAL_PATTERNS", [])
AUTHORITY_PATTERNS: List[str] = _PATTERNS.get("AUTHORITY_PATTERNS", [])
SCARE_TACTICS: List[str] = _PATTERNS.get("SCARE_TACTICS", [])
SUSPICIOUS_URLS: List[str] = _PATTERNS.get("SUSPICIOUS_URLS", [])

# ---------- Compile Regular Expressions ----------
def _compile_regex(patterns: List[str]) -> re.Pattern:
    """Compile a list of patterns into a single regex, sorted by length for efficiency."""
    if not patterns:
        return re.compile("$^")  # Never matches
    # Escape and sort by length descending for better matching
    escaped = [re.escape(p) for p in patterns]
    sorted_patterns = sorted(escaped, key=len, reverse=True)
    return re.compile("|".join(sorted_patterns), re.IGNORECASE)

URGENCY_RE = _compile_regex(URGENCY_PATTERNS)
FINANCIAL_RE = _compile_regex(FINANCIAL_PATTERNS)
CREDENTIAL_RE = _compile_regex(CREDENTIAL_PATTERNS)
AUTHORITY_RE = _compile_regex(AUTHORITY_PATTERNS)
SCARE_RE = _compile_regex(SCARE_TACTICS)
SUSPICIOUS_URLS_RE = _compile_regex(SUSPICIOUS_URLS)

# Additional regex patterns
IP_LINK_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", re.IGNORECASE)
SUSPICIOUS_TLD_REGEX = re.compile(r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)", re.IGNORECASE)

# ---------- Sets for Fast Membership ----------
TOP_50_SPOOFED: Set[str] = set(_PATTERNS.get("TOP_50_SPOOFED", _FALLBACK_PATTERNS["TOP_50_SPOOFED"]))
URL_SHORTENERS: Set[str] = set(_PATTERNS.get("URL_SHORTENERS", _FALLBACK_PATTERNS["URL_SHORTENERS"]))


# ---------- Levenshtein Distance ----------
def levenshtein(s1: str, s2: str) -> int:
    """
    Compute Levenshtein edit distance between two strings.

    Optimised with early exit if the length difference is large.
    """
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    # If length difference > 2, return early (typosquatting is usually 1-2 edits)
    if len(s1) - len(s2) > 2:
        return len(s1) - len(s2)  # Not exact, but good enough for filtering
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


# ---------- Utility Functions ----------
def reload_patterns() -> Dict[str, List[str]]:
    """
    Reload threat patterns from the JSON file (useful for development).

    Returns:
        The newly loaded patterns dictionary.
    """
    global _PATTERNS
    global URGENCY_PATTERNS, FINANCIAL_PATTERNS, CREDENTIAL_PATTERNS
    global AUTHORITY_PATTERNS, SCARE_TACTICS, SUSPICIOUS_URLS
    global URGENCY_RE, FINANCIAL_RE, CREDENTIAL_RE, AUTHORITY_RE, SCARE_RE, SUSPICIOUS_URLS_RE
    global TOP_50_SPOOFED, URL_SHORTENERS

    _PATTERNS = load_threat_patterns()

    URGENCY_PATTERNS = _PATTERNS.get("URGENCY_PATTERNS", [])
    FINANCIAL_PATTERNS = _PATTERNS.get("FINANCIAL_PATTERNS", [])
    CREDENTIAL_PATTERNS = _PATTERNS.get("CREDENTIAL_PATTERNS", [])
    AUTHORITY_PATTERNS = _PATTERNS.get("AUTHORITY_PATTERNS", [])
    SCARE_TACTICS = _PATTERNS.get("SCARE_TACTICS", [])
    SUSPICIOUS_URLS = _PATTERNS.get("SUSPICIOUS_URLS", [])

    URGENCY_RE = _compile_regex(URGENCY_PATTERNS)
    FINANCIAL_RE = _compile_regex(FINANCIAL_PATTERNS)
    CREDENTIAL_RE = _compile_regex(CREDENTIAL_PATTERNS)
    AUTHORITY_RE = _compile_regex(AUTHORITY_PATTERNS)
    SCARE_RE = _compile_regex(SCARE_TACTICS)
    SUSPICIOUS_URLS_RE = _compile_regex(SUSPICIOUS_URLS)

    TOP_50_SPOOFED = set(_PATTERNS.get("TOP_50_SPOOFED", _FALLBACK_PATTERNS["TOP_50_SPOOFED"]))
    URL_SHORTENERS = set(_PATTERNS.get("URL_SHORTENERS", _FALLBACK_PATTERNS["URL_SHORTENERS"]))

    logger.info("Threat patterns reloaded.")
    return _PATTERNS


def get_patterns() -> Dict[str, List[str]]:
    """Return the current patterns dictionary (for debugging/inspection)."""
    return {
        "URGENCY_PATTERNS": URGENCY_PATTERNS,
        "FINANCIAL_PATTERNS": FINANCIAL_PATTERNS,
        "CREDENTIAL_PATTERNS": CREDENTIAL_PATTERNS,
        "AUTHORITY_PATTERNS": AUTHORITY_PATTERNS,
        "SCARE_TACTICS": SCARE_TACTICS,
        "SUSPICIOUS_URLS": SUSPICIOUS_URLS,
        "TOP_50_SPOOFED": list(TOP_50_SPOOFED),
        "URL_SHORTENERS": list(URL_SHORTENERS),
    }