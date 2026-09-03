"""
DNS-based SPF, DKIM, and DMARC record validation.

Performs live DNS TXT lookups to validate email authentication records.
Complements the header-only parsing from parser.py with authoritative DNS data.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------- Models ----------
class DNSAuthRecord(BaseModel):
    """DNS authentication results for a domain."""
    domain: str = Field(..., min_length=1)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    spf_valid: bool = False
    dmarc_policy: Optional[str] = None  # "none" | "quarantine" | "reject"
    dmarc_pct: int = Field(default=100, ge=0, le=100)
    score_penalty: int = Field(default=0, ge=0)


# ---------- Constants ----------
SPF_TAG = "v=spf1"
DMARC_TAG = "v=DMARC1"
DNS_TIMEOUT = 5  # seconds
PENALTY_NO_SPF = 10
PENALTY_NO_DMARC = 10
PENALTY_WEAK_DMARC = 5


class DnsValidator:
    """Perform live DNS TXT lookups to validate SPF and DMARC."""

    @staticmethod
    async def validate(domain: str) -> DNSAuthRecord:
        """
        Look up SPF and DMARC records for the given domain.

        Args:
            domain: Domain name to query (e.g., "example.com").

        Returns:
            DNSAuthRecord with parsed records and penalties.
        """
        if not domain or not domain.strip():
            raise ValueError("domain is required")

        # Run lookups concurrently
        spf_task = asyncio.to_thread(DnsValidator._get_spf, domain)
        dmarc_task = asyncio.to_thread(DnsValidator._get_dmarc, domain)
        spf_rec, dmarc_rec = await asyncio.gather(spf_task, dmarc_task)

        spf_valid = spf_rec is not None and spf_rec.lower().startswith(SPF_TAG.lower())

        dmarc_policy = None
        dmarc_pct = 100
        if dmarc_rec:
            # Parse policy: p=none, p=quarantine, p=reject
            pol_m = re.search(r"p=(\w+)", dmarc_rec, re.IGNORECASE)
            dmarc_policy = pol_m.group(1).lower() if pol_m else None
            # Parse percentage
            pct_m = re.search(r"pct=(\d+)", dmarc_rec, re.IGNORECASE)
            dmarc_pct = int(pct_m.group(1)) if pct_m else 100

        # Compute penalty (higher penalty = worse security)
        penalty = 0
        if not spf_valid:
            penalty += PENALTY_NO_SPF
        if not dmarc_rec:
            penalty += PENALTY_NO_DMARC
        if dmarc_policy in (None, "none"):
            penalty += PENALTY_WEAK_DMARC

        logger.info("DNS validation for %s: SPF=%s, DMARC=%s, penalty=%d",
                    domain, spf_valid, dmarc_policy, penalty)

        return DNSAuthRecord(
            domain=domain,
            spf_record=spf_rec,
            dmarc_record=dmarc_rec,
            spf_valid=spf_valid,
            dmarc_policy=dmarc_policy,
            dmarc_pct=dmarc_pct,
            score_penalty=penalty,
        )

    @staticmethod
    def _get_spf(domain: str) -> Optional[str]:
        """Query SPF TXT record for the domain."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_TIMEOUT)
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith(SPF_TAG.lower()):
                    return txt
        except dns.resolver.NXDOMAIN:
            logger.debug("No SPF record found for %s", domain)
        except dns.resolver.Timeout:
            logger.warning("DNS timeout for SPF lookup on %s", domain)
        except Exception as e:
            logger.warning("SPF lookup failed for %s: %s", domain, e)
        return None

    @staticmethod
    def _get_dmarc(domain: str) -> Optional[str]:
        """Query DMARC TXT record at _dmarc.domain."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_TIMEOUT)
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith(DMARC_TAG.lower()):
                    return txt
        except dns.resolver.NXDOMAIN:
            logger.debug("No DMARC record found for %s", domain)
        except dns.resolver.Timeout:
            logger.warning("DNS timeout for DMARC lookup on %s", domain)
        except Exception as e:
            logger.warning("DMARC lookup failed for %s: %s", domain, e)
        return None