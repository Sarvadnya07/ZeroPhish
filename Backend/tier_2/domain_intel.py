"""
Domain Intelligence and WHOIS utilities for Tier 2 evaluation.

Provides domain age retrieval (with both legacy and modern async clients)
and scoring logic with configurable thresholds.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional, Tuple, Union

import whois

logger = logging.getLogger(__name__)

# ---------- Configuration ----------
NEW_DOMAIN_DAYS = int(os.getenv("DOMAIN_NEW_DAYS", "30"))
ESTABLISHED_DOMAIN_DAYS = int(os.getenv("DOMAIN_ESTABLISHED_DAYS", "365"))
SCORE_NEW = float(os.getenv("DOMAIN_SCORE_NEW", "100.0"))
SCORE_SUSPICIOUS = float(os.getenv("DOMAIN_SCORE_SUSPICIOUS", "60.0"))
SCORE_OK = float(os.getenv("DOMAIN_SCORE_OK", "10.0"))
SCORE_UNKNOWN = float(os.getenv("DOMAIN_SCORE_UNKNOWN", "70.0"))
WEIGHT_DOMAIN = float(os.getenv("DOMAIN_WEIGHT", "0.3"))


def analyze_domain_age(age_days: Optional[int]) -> Tuple[float, str, str]:
    """
    Analyze domain age and return (score, status, evidence_message).

    Args:
        age_days: Domain age in days, or None if unknown.

    Returns:
        Tuple of (score 0-100, status string, evidence message).
    """
    if age_days is None:
        return SCORE_UNKNOWN, "UNKNOWN", "Could not verify domain age."
    elif age_days < NEW_DOMAIN_DAYS:
        return SCORE_NEW, "CRITICAL", f"Domain is very new ({age_days} days old)."
    elif age_days < ESTABLISHED_DOMAIN_DAYS:
        return SCORE_SUSPICIOUS, "SUSPICIOUS", f"Domain is relatively new ({age_days} days old)."
    else:
        return SCORE_OK, "OK", f"Domain is established ({age_days} days old)."


def get_domain_age(domain: str) -> int:
    """
    Legacy synchronous WHOIS lookup. Returns age in days (0 if unknown/error).

    Prefer the async `aget_domain_age()` for production use.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        # Normalise to timezone‑aware UTC
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age = (now - creation_date).days
        return max(0, age)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return 0


async def aget_domain_age(
    domain: str,
    cache_client: Optional[Any] = None,
    use_enhanced: bool = True,
) -> int:
    """
    Asynchronously retrieve domain age using the enhanced WHOIS client (if available).

    Args:
        domain: Domain name to check.
        cache_client: Optional cache client (e.g., Redis) for caching results.
        use_enhanced: If True, attempt to use the modern async WHOIS client.

    Returns:
        Age in days, or 0 if unavailable.
    """
    # Option 1: Use enhanced WHOIS client (if available and requested)
    if use_enhanced:
        try:
            from tier_2.whois_client import get_whois_client

            client = await get_whois_client(cache_client=cache_client)
            age, source = await client.get_domain_age(domain)
            if age is not None:
                logger.debug("Domain %s age: %d days (source: %s)", domain, age, source)
                return age
        except ImportError:
            logger.debug("Enhanced WHOIS client not available, falling back to legacy.")
        except Exception as e:
            logger.warning("Enhanced WHOIS lookup failed for %s: %s", domain, e)

    # Option 2: Legacy synchronous WHOIS (blocking but fallback)
    try:
        loop = asyncio.get_event_loop()
        age = await loop.run_in_executor(None, get_domain_age, domain)
        return age
    except Exception as e:
        logger.warning("Legacy WHOIS lookup failed for %s: %s", domain, e)
        return 0


def get_domain_score(domain: str, age_days: Optional[int] = None) -> Tuple[float, str, str]:
    """
    Convenience function: get domain age (if not provided) and return score.

    Args:
        domain: Domain name.
        age_days: Optional pre‑computed age; if None, retrieved synchronously.

    Returns:
        Tuple of (score, status, evidence).
    """
    if age_days is None:
        # Legacy synchronous retrieval
        age_days = get_domain_age(domain)
    return analyze_domain_age(age_days)