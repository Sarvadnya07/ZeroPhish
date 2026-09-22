"""
Domain Intelligence and WHOIS / RDAP utilities for Tier 2 evaluation.

Provides domain age retrieval (with both legacy and modern async clients)
and scoring logic with configurable thresholds and uncertainty-safe semantics.
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
# Default SCORE_UNKNOWN to 50.0 (neutral uncertainty, neither safe 10.0 nor suspicious 70.0)
SCORE_UNKNOWN = float(os.getenv("DOMAIN_SCORE_UNKNOWN", "50.0"))
WEIGHT_DOMAIN = float(os.getenv("DOMAIN_WEIGHT", "0.3"))


def analyze_domain_age(
    age_days: Optional[int],
    lookup_status: Optional[str] = None,
) -> Tuple[float, str, str]:
    """
    Analyze domain age and return (score, status, evidence_message).

    Adheres to Phase 1.4 semantics:
    - Verified new (< 30 days) -> CRITICAL (100.0)
    - Verified relatively new (< 365 days) -> SUSPICIOUS (60.0)
    - Verified established (>= 365 days) -> OK (10.0)
    - Missing / timeout / lookup failed -> UNKNOWN (50.0) with explicit explanation.

    Args:
        age_days: Domain age in days, or None if unknown.
        lookup_status: Optional detail string ("LOOKUP_FAILED", "UNKNOWN", etc.)

    Returns:
        Tuple of (score 0-100, status string, evidence message).
    """
    if age_days is None:
        if lookup_status == "LOOKUP_FAILED":
            return SCORE_UNKNOWN, "UNKNOWN", "Could not verify domain age (lookup timed out or provider unavailable)."
        elif lookup_status == "UNKNOWN":
            return SCORE_UNKNOWN, "UNKNOWN", "Domain registration date is unlisted or missing."
        return SCORE_UNKNOWN, "UNKNOWN", "Could not verify domain age."
    elif age_days < NEW_DOMAIN_DAYS:
        return SCORE_NEW, "CRITICAL", f"Domain is very new ({age_days} days old)."
    elif age_days < ESTABLISHED_DOMAIN_DAYS:
        return SCORE_SUSPICIOUS, "SUSPICIOUS", f"Domain is relatively new ({age_days} days old)."
    else:
        return SCORE_OK, "OK", f"Domain is established ({age_days} days old)."


def get_domain_age(domain: str) -> Optional[int]:
    """
    Synchronous WHOIS lookup with bounded socket parsing.
    Returns age in days, or None if unknown/error.
    """
    try:
        w = whois.whois(domain)
        creation_date = getattr(w, "creation_date", None)
        if creation_date is None:
            return None
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if not creation_date:
            return None

        if not isinstance(creation_date, datetime):
            try:
                creation_date = datetime.fromisoformat(str(creation_date))
            except (ValueError, TypeError):
                return None

        # Normalise to timezone‑aware UTC
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age = (now - creation_date).days
        return max(0, age)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return None


async def aget_domain_age(
    domain: str,
    cache_client: Optional[Any] = None,
    use_enhanced: bool = True,
) -> Optional[int]:
    """
    Asynchronously retrieve domain age using the enhanced WHOIS & RDAP client.

    Args:
        domain: Domain name to check.
        cache_client: Optional cache client (e.g., Redis) for caching results.
        use_enhanced: If True, attempt to use the modern async WHOIS/RDAP client.

    Returns:
        Age in days, or None if unavailable.
    """
    if use_enhanced:
        try:
            try:
                from .whois_client import get_whois_client
            except ImportError:
                from tier_2.whois_client import get_whois_client

            client = await get_whois_client(cache_client=cache_client)
            age, source = await client.get_domain_age(domain)
            if age is not None:
                logger.debug("Domain %s age: %d days (source: %s)", domain, age, source)
                return age
            return None
        except Exception as e:
            logger.warning("Enhanced WHOIS/RDAP lookup failed for %s: %s", domain, e)

    # Option 2: Fallback synchronous WHOIS in executor
    try:
        loop = asyncio.get_event_loop()
        age = await loop.run_in_executor(None, get_domain_age, domain)
        return age
    except Exception as e:
        logger.warning("Legacy WHOIS lookup failed for %s: %s", domain, e)
        return None


async def aget_domain_intel(
    domain: str,
    cache_client: Optional[Any] = None,
) -> Tuple[float, str, str]:
    """
    Asynchronously retrieve full domain intelligence and return (score, status, evidence).
    """
    try:
        try:
            from .whois_client import get_whois_client
        except ImportError:
            from tier_2.whois_client import get_whois_client

        client = await get_whois_client(cache_client=cache_client)
        age, status_label, source = await client.get_domain_intel(domain)
        return analyze_domain_age(age, lookup_status=status_label)
    except Exception as e:
        logger.warning("Domain intel lookup failed for %s: %s", domain, e)
        return analyze_domain_age(None, lookup_status="LOOKUP_FAILED")


def get_domain_score(domain: str, age_days: Optional[int] = None) -> Tuple[float, str, str]:
    """
    Convenience function: get domain age (if not provided) and return score.
    """
    if age_days is None:
        age_days = get_domain_age(domain)
    return analyze_domain_age(age_days)