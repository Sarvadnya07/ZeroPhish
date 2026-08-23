"""
ThreatAnalyzer — Core detection engine decomposed into clean, cohesive analysis stages.
Pure library independent of web frameworks, server startup, and ports.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel

from .rules import (
    AUTHORITY_PATTERNS,
    AUTHORITY_RE,
    CREDENTIAL_PATTERNS,
    CREDENTIAL_RE,
    FINANCIAL_PATTERNS,
    FINANCIAL_RE,
    IP_LINK_REGEX,
    SCARE_RE,
    SCARE_TACTICS,
    SUSPICIOUS_TLD_REGEX,
    SUSPICIOUS_URLS,
    SUSPICIOUS_URLS_RE,
    TOP_50_SPOOFED,
    URGENCY_PATTERNS,
    URGENCY_RE,
    URL_SHORTENERS,
    levenshtein,
)

logger = logging.getLogger(__name__)

try:
    from tier_2.ml_model import get_ml_model

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    get_ml_model = None  # type: ignore[assignment]


class ThreatAnalysis(BaseModel):
    """Pydantic model representing Threat Analysis output."""

    threat_level: int
    category: str
    reasoning: str
    flagged_phrases: List[str]


class ThreatAnalyzer:
    """Local threat analysis engine (combines OSINT, pattern heuristics, and ML)."""

    # Expose rule properties for backward compatibility
    URGENCY_PATTERNS = URGENCY_PATTERNS
    FINANCIAL_PATTERNS = FINANCIAL_PATTERNS
    CREDENTIAL_PATTERNS = CREDENTIAL_PATTERNS
    AUTHORITY_PATTERNS = AUTHORITY_PATTERNS
    SCARE_TACTICS = SCARE_TACTICS
    SUSPICIOUS_URLS = SUSPICIOUS_URLS

    URGENCY_RE = URGENCY_RE
    FINANCIAL_RE = FINANCIAL_RE
    CREDENTIAL_RE = CREDENTIAL_RE
    AUTHORITY_RE = AUTHORITY_RE
    SCARE_RE = SCARE_RE
    SUSPICIOUS_URLS_RE = SUSPICIOUS_URLS_RE

    IP_LINK_REGEX = IP_LINK_REGEX
    SUSPICIOUS_TLD_REGEX = SUSPICIOUS_TLD_REGEX
    TOP_50_SPOOFED = TOP_50_SPOOFED
    URL_SHORTENERS = URL_SHORTENERS

    @staticmethod
    def levenshtein(s1: str, s2: str) -> int:
        return levenshtein(s1, s2)

    @classmethod
    async def track_redirects(cls, url: str) -> Tuple[str, List[str]]:
        """Follow redirects for suspicious URLs / shorteners."""
        if not url.startswith("http"):
            return url, []
        try:
            import httpx

            async with httpx.AsyncClient(
                timeout=2.0, follow_redirects=True, max_redirects=3
            ) as client:
                response = await client.head(url)
                return str(response.url), []
        except Exception:
            return url, ["redirect_timeout"]

    @classmethod
    def _extract_linguistic_patterns(cls, body_lower: str) -> Tuple[Dict[str, int], List[str]]:
        """Stage 1: Scan body for urgency, financial, credential, authority, and scare markers."""
        scores = {
            "urgency": 0,
            "financial": 0,
            "credential": 0,
            "authority": 0,
            "scare": 0,
        }
        flagged: List[str] = []

        urgency_matches = set(cls.URGENCY_RE.findall(body_lower))
        if urgency_matches:
            scores["urgency"] = len(urgency_matches) * 10
            flagged.extend(sorted(urgency_matches))

        financial_matches = set(cls.FINANCIAL_RE.findall(body_lower))
        if financial_matches:
            scores["financial"] = len(financial_matches) * 8
            flagged.extend(sorted(financial_matches))

        credential_matches = set(cls.CREDENTIAL_RE.findall(body_lower))
        if credential_matches:
            scores["credential"] = len(credential_matches) * 7
            flagged.extend(sorted(credential_matches))

        authority_matches = set(cls.AUTHORITY_RE.findall(body_lower))
        if authority_matches:
            scores["authority"] = len(authority_matches) * 9
            flagged.extend(sorted(authority_matches))

        scare_matches = set(cls.SCARE_RE.findall(body_lower))
        if scare_matches:
            scores["scare"] = len(scare_matches) * 8
            flagged.extend(sorted(scare_matches))

        return scores, flagged

    @classmethod
    async def _analyze_links(cls, links: List[str]) -> Tuple[int, List[str]]:
        """Stage 2: Evaluate URL features, IP addresses, Punycode, TLDs, and shortener redirects."""
        link_score = 0
        flagged: List[str] = []

        for link in links or []:
            lowered_link = (link or "").lower()
            domain_match = re.search(r"https?://([^/]+)", lowered_link)
            domain = domain_match.group(1) if domain_match else ""

            suspicious_match = cls.SUSPICIOUS_URLS_RE.search(lowered_link)
            if suspicious_match:
                link_score += 15
                flagged.append(f"suspicious_url:{suspicious_match.group()}")

            if cls.IP_LINK_REGEX.search(lowered_link):
                link_score += 20
                flagged.append("ip_based_link")

            if "xn--" in lowered_link:
                link_score += 18
                flagged.append("punycode_link")

            if cls.SUSPICIOUS_TLD_REGEX.search(lowered_link):
                link_score += 10
                flagged.append("suspicious_tld")

            if any(shortener in domain for shortener in cls.URL_SHORTENERS):
                link_score += 5
                final_url, _ = await cls.track_redirects(link)
                if final_url != link:
                    flagged.append("hidden_redirect")
                    if cls.SUSPICIOUS_TLD_REGEX.search(final_url.lower()):
                        link_score += 20
                        flagged.append("redirect_to_suspicious_tld")

        return link_score, flagged

    @classmethod
    def _analyze_sender(cls, sender_lower: str) -> Tuple[int, List[str]]:
        """Stage 3: Validate sender address structure and detect typosquatting of known brands."""
        authority_score = 0
        flagged: List[str] = []

        if "@" not in sender_lower:
            authority_score += 10
            flagged.append("invalid_sender_format")
        else:
            sender_domain = sender_lower.split("@")[-1]
            if any(term in sender_lower for term in ("security", "support", "admin", "billing")):
                authority_score += 5

            for target in cls.TOP_50_SPOOFED:
                if sender_domain == target:
                    break
                dist = cls.levenshtein(sender_domain, target)
                if dist in (1, 2):
                    authority_score += 40
                    flagged.append(f"typosquatting:{target}")
                    break

        return authority_score, flagged

    @classmethod
    def _aggregate_base_score(
        cls, pattern_scores: Dict[str, int], sender_score: int, link_score: int
    ) -> float:
        """Stage 4: Combine feature scores and apply compound escalation rules."""
        urgency = pattern_scores["urgency"]
        financial = pattern_scores["financial"]
        credential = pattern_scores["credential"]
        authority = pattern_scores["authority"] + sender_score
        scare = pattern_scores["scare"]

        base_threat = min(
            100.0, float(urgency + financial + credential + authority + scare + link_score)
        )

        if urgency > 0 and (financial > 0 or credential > 0):
            base_threat = min(100.0, base_threat + 20.0)

        if authority > 0 and (financial > 0 or scare > 0):
            base_threat = min(100.0, base_threat + 25.0)

        return base_threat

    @classmethod
    def _build_category_and_reasoning(
        cls, pattern_scores: Dict[str, int], sender_score: int, link_score: int, base_threat: float
    ) -> Tuple[str, str]:
        """Stage 5: Synthesize human-understandable threat categories and reasoning."""
        categories: List[str] = []
        if pattern_scores["urgency"] > 0:
            categories.append("Urgency")
        if pattern_scores["financial"] > 0:
            categories.append("Financial")
        if pattern_scores["credential"] > 0:
            categories.append("Credential")
        if (pattern_scores["authority"] + sender_score) > 0:
            categories.append("Authority")
        if pattern_scores["scare"] > 0:
            categories.append("ScareTactics")
        if link_score > 0:
            categories.append("SuspiciousLinks")

        if not categories and base_threat < 20:
            category = "Safe"
            reasoning = "No significant threat indicators detected"
        elif not categories:
            category = "GeneralSuspicion"
            reasoning = "Suspicious signals detected but not enough to classify a specific category"
        else:
            category = "/".join(categories[:3])
            reasoning = f"Detected {len(categories)} threat categories: {', '.join(categories)}"

        return category, reasoning

    @classmethod
    async def _apply_ml_enhancement(
        cls, email_body: str, base_threat: float, category: str, reasoning: str, use_ml: bool
    ) -> Tuple[float, str, str]:
        """Stage 6: Apply fine-tuned HuggingFace text classifier inference if enabled."""
        if not (use_ml and ML_AVAILABLE and os.getenv("ML_ENABLED", "true").lower() == "true"):
            return base_threat, category, reasoning

        try:
            ml_model = await get_ml_model()
            if ml_model.is_loaded():
                ml_score, ml_confidence = await ml_model.predict(email_body)
                logger.debug("ML prediction: score=%.2f, confidence=%s", ml_score, ml_confidence)

                # Fuse: ML (60%) + Pattern heuristics (40%)
                combined_threat = (ml_score * 0.6) + (base_threat * 0.4)

                if ml_confidence == "phishing" and "ML:Phishing" not in category:
                    category = f"{category}/ML:Phishing" if category != "Safe" else "ML:Phishing"

                reasoning = f"{reasoning}. ML confidence: {ml_confidence} ({ml_score:.1f}%)"
                return combined_threat, category, reasoning
        except Exception as e:
            logger.warning("ML inference failed in analyzer: %s", e)

        return base_threat, category, reasoning

    @classmethod
    async def analyze_threat(
        cls, email_body: str, sender: str, links: List[str], use_ml: bool = True
    ) -> ThreatAnalysis:
        """
        Analyze email for threat indicators using structured pipeline stages.
        """
        body_lower = (email_body or "").lower()
        sender_lower = (sender or "").lower()

        # 1. Text patterns
        pattern_scores, text_flags = cls._extract_linguistic_patterns(body_lower)

        # 2. Links & Shorteners
        link_score, link_flags = await cls._analyze_links(links)

        # 3. Sender domain & typosquatting
        sender_score, sender_flags = cls._analyze_sender(sender_lower)

        # 4. Aggregation
        base_threat = cls._aggregate_base_score(pattern_scores, sender_score, link_score)

        # 5. Explanations
        category, reasoning = cls._build_category_and_reasoning(
            pattern_scores, sender_score, link_score, base_threat
        )

        # 6. ML Layer
        final_threat, category, reasoning = await cls._apply_ml_enhancement(
            email_body, base_threat, category, reasoning, use_ml
        )

        # Deduplicate flagged phrases preserving discovery order
        all_flags = text_flags + link_flags + sender_flags
        deduped_flags: List[str] = []
        seen = set()
        for phrase in all_flags:
            if phrase not in seen:
                seen.add(phrase)
                deduped_flags.append(phrase)

        return ThreatAnalysis(
            threat_level=int(min(100, max(0, round(final_threat)))),
            category=category,
            reasoning=reasoning,
            flagged_phrases=deduped_flags[:10],
        )
