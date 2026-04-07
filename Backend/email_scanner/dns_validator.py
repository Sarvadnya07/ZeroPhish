"""
DNS-based SPF, DKIM, and DMARC record validation.
Complements the header-only parsing from parser.py with live DNS lookups.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional, Tuple

from pydantic import BaseModel


class DNSAuthRecord(BaseModel):
    domain: str
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    spf_valid: bool = False
    dmarc_policy: Optional[str] = None   # "none" | "quarantine" | "reject"
    dmarc_pct: int = 100
    score_penalty: int = 0


class DnsValidator:
    """Perform live DNS TXT lookups to validate SPF and DMARC."""

    @staticmethod
    async def validate(domain: str) -> DNSAuthRecord:
        spf_task   = asyncio.to_thread(DnsValidator._get_spf, domain)
        dmarc_task = asyncio.to_thread(DnsValidator._get_dmarc, domain)
        spf_rec, dmarc_rec = await asyncio.gather(spf_task, dmarc_task)

        spf_valid = spf_rec is not None and spf_rec.startswith("v=spf1")
        dmarc_policy = None
        dmarc_pct = 100

        if dmarc_rec:
            pol_m = re.search(r"p=(\w+)", dmarc_rec)
            pct_m = re.search(r"pct=(\d+)", dmarc_rec)
            dmarc_policy = pol_m.group(1) if pol_m else None
            dmarc_pct    = int(pct_m.group(1)) if pct_m else 100

        penalty = 0
        if not spf_valid:    penalty += 10
        if not dmarc_rec:    penalty += 10
        if dmarc_policy in (None, "none"):  penalty += 5

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
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return txt
        except Exception:
            pass
        return None

    @staticmethod
    def _get_dmarc(domain: str) -> Optional[str]:
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
            for r in answers:
                txt = r.to_text().strip('"')
                if "v=DMARC1" in txt or "v=dmarc1" in txt:
                    return txt
        except Exception:
            pass
        return None
