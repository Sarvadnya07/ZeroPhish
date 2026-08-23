"""
Domain Intelligence and WHOIS utilities for Tier 2 evaluation.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Tuple

import whois

logger = logging.getLogger(__name__)


def analyze_domain_age(age_days: int) -> Tuple[float, str, str]:
    """Analyze domain age and return (score, status, evidence_message)."""
    if age_days == 0:
        return 70.0, "UNKNOWN", "Could not verify domain age."
    elif age_days < 30:
        return 100.0, "CRITICAL", f"Domain is very new ({age_days} days old)."
    elif age_days < 365:
        return 60.0, "SUSPICIOUS", f"Domain is relatively new ({age_days} days old)."
    else:
        return 10.0, "OK", f"Domain is established ({age_days} days old)."


def get_domain_age(domain: str) -> int:
    """Tier 2: WHOIS Check. Returns age in days."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        # Handle timezone-aware and timezone-naive datetimes
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age = (now - creation_date).days
        return max(0, age)
    except Exception as e:
        logger.error("WHOIS lookup failed for %s: %s", domain, e)
        return 0
