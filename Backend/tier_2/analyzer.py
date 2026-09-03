"""
ThreatAnalyzer — Core detection engine decomposed into clean, cohesive analysis stages.

Pure library independent of web frameworks, server startup, and ports.
Implements a multi‑stage pipeline:
1. Linguistic pattern extraction (urgency, financial, credential, authority, scare)
2. Link analysis (IP, Punycode, suspicious TLDs, redirect tracking)
3. Sender analysis (typosquatting detection)
4. Score aggregation with compound escalation rules
5. Category and reasoning synthesis
6. Optional ML enhancement (DistilBERT via tier_2.ml_model)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

# Import rule sets from local module
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

# ---------- Constants ----------
ML_AVAILABLE = False
try:
    from tier_2.ml_model import get_ml_model
    ML_AVAILABLE = True
except ImportError:
    get_ml_model = None  # type: ignore[assignment]

# Default weights
PATTERN_WEIGHTS = {
    "urgency": 10,
    "financial": 8,
    "credential": 7,
    "authority": 9,
    "scare": 8,
}

COMPOUND_BONUS_URGENT_FINANCIAL = 20.0
COMPOUND_BONUS_AUTHORITY_FINANCIAL = 25.0
ML_WEIGHT = 0.60
PATTERN_WEIGHT = 0.40
DEFAULT_ML_ENABLED = True
MAX_FLAGGED_PHRASES = 10


# ---------- Pydantic Model ----------
class ThreatAnalysis(BaseModel):
    """Pydantic model representing Threat Analysis output."""
    threat_level: int = Field(..., ge=0, le=100)
    category: str
    reasoning: str
    flagged_phrases: List[str] = Field(default_factory=list)


# ---------- Core Analyzer ----------
class ThreatAnalyzer:
    """
    Local threat analysis engine combining OSINT, pattern heuristics, and ML.

    All methods are classmethods for easy testing and use without instantiation.
    """

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
        """
        Follow redirects for suspicious URLs / shorteners.

        Returns:
            (final_url, flags) where flags is a list of issues (e.g., "redirect_timeout").
        """
        if not url.startswith("http"):
            return url, []
        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=2.0,
                follow_redirects=True,
                max_redirects=3,
                verify=False,  # Allow self-signed for staging
            ) as client:
                response = await client.head(url)
                return str(response.url), []
        except httpx.TimeoutException:
            return url, ["redirect_timeout"]
        except Exception as e:
            logger.debug("Redirect tracking failed for %s: %s", url[:50], e)
            return url, ["redirect_error"]

    @classmethod
    def _extract_linguistic_patterns(cls, body_lower: str) -> Tuple[Dict[str, int], List[str]]:
        """
        Stage 1: Scan body for urgency, financial, credential, authority, and scare markers.

        Returns:
            (pattern_scores, flagged_phrases)
        """
        scores = {"urgency": 0, "financial": 0, "credential": 0, "authority": 0, "scare": 0}
        flagged: List[str] = []

        urgency_matches = set(cls.URGENCY_RE.findall(body_lower))
        if urgency_matches:
            scores["urgency"] = len(urgency_matches) * PATTERN_WEIGHTS["urgency"]
            flagged.extend(sorted(urgency_matches))

        financial_matches = set(cls.FINANCIAL_RE.findall(body_lower))
        if financial_matches:
            scores["financial"] = len(financial_matches) * PATTERN_WEIGHTS["financial"]
            flagged.extend(sorted(financial_matches))

        credential_matches = set(cls.CREDENTIAL_RE.findall(body_lower))
        if credential_matches:
            scores["credential"] = len(credential_matches) * PATTERN_WEIGHTS["credential"]
            flagged.extend(sorted(credential_matches))

        authority_matches = set(cls.AUTHORITY_RE.findall(body_lower))
        if authority_matches:
            scores["authority"] = len(authority_matches) * PATTERN_WEIGHTS["authority"]
            flagged.extend(sorted(authority_matches))

        scare_matches = set(cls.SCARE_RE.findall(body_lower))
        if scare_matches:
            scores["scare"] = len(scare_matches) * PATTERN_WEIGHTS["scare"]
            flagged.extend(sorted(scare_matches))

        return scores, flagged

    @classmethod
    async def _analyze_links(cls, links: List[str]) -> Tuple[int, List[str]]:
        """
        Stage 2: Evaluate URL features, IP addresses, Punycode, TLDs, and shortener redirects.

        Returns:
            (link_score, flagged_phrases)
        """
        link_score = 0
        flagged: List[str] = []

        for link in links or []:
            if not link:
                continue
            lowered_link = link.lower()
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
                final_url, redirect_flags = await cls.track_redirects(link)
                flagged.extend(redirect_flags)
                if final_url != link:
                    flagged.append("hidden_redirect")
                    if cls.SUSPICIOUS_TLD_REGEX.search(final_url.lower()):
                        link_score += 20
                        flagged.append("redirect_to_suspicious_tld")

        return link_score, flagged

    @classmethod
    def _analyze_sender(cls, sender_lower: str) -> Tuple[int, List[str]]:
        """
        Stage 3: Validate sender address structure and detect typosquatting.

        Returns:
            (sender_score, flagged_phrases)
        """
        sender_score = 0
        flagged: List[str] = []

        if "@" not in sender_lower:
            sender_score += 10
            flagged.append("invalid_sender_format")
        else:
            sender_domain = sender_lower.split("@")[-1]
            if any(term in sender_lower for term in ("security", "support", "admin", "billing")):
                sender_score += 5
                flagged.append("suspicious_sender_keyword")

            # Typosquatting detection
            for target in cls.TOP_50_SPOOFED:
                if sender_domain == target:
                    break
                dist = cls.levenshtein(sender_domain, target)
                if 1 <= dist <= 2:
                    sender_score += 40
                    flagged.append(f"typosquatting:{target}")
                    break

        return sender_score, flagged

    @classmethod
    def _aggregate_base_score(
        cls,
        pattern_scores: Dict[str, int],
        sender_score: int,
        link_score: int,
    ) -> float:
        """
        Stage 4: Combine feature scores and apply compound escalation rules.
        """
        urgency = pattern_scores["urgency"]
        financial = pattern_scores["financial"]
        credential = pattern_scores["credential"]
        authority = pattern_scores["authority"] + sender_score
        scare = pattern_scores["scare"]

        base_threat = min(
            100.0,
            float(urgency + financial + credential + authority + scare + link_score)
        )

        # Compound bonuses
        if urgency > 0 and (financial > 0 or credential > 0):
            base_threat = min(100.0, base_threat + COMPOUND_BONUS_URGENT_FINANCIAL)

        if authority > 0 and (financial > 0 or scare > 0):
            base_threat = min(100.0, base_threat + COMPOUND_BONUS_AUTHORITY_FINANCIAL)

        return base_threat

    @classmethod
    def _build_category_and_reasoning(
        cls,
        pattern_scores: Dict[str, int],
        sender_score: int,
        link_score: int,
        base_threat: float,
    ) -> Tuple[str, str]:
        """
        Stage 5: Synthesise human-understandable threat categories and reasoning.
        """
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
        cls,
        email_body: str,
        base_threat: float,
        category: str,
        reasoning: str,
        use_ml: bool,
    ) -> Tuple[float, str, str]:
        """
        Stage 6: Apply fine-tuned HuggingFace text classifier inference if enabled.
        """
        if not (use_ml and ML_AVAILABLE and os.getenv("ML_ENABLED", "true").lower() == "true"):
            return base_threat, category, reasoning

        try:
            ml_model = await get_ml_model()  # type: ignore[call-arg]
            if ml_model.is_loaded():
                ml_score, ml_confidence = await ml_model.predict(email_body)
                logger.debug("ML prediction: score=%.2f, confidence=%s", ml_score, ml_confidence)

                combined_threat = (ml_score * ML_WEIGHT) + (base_threat * PATTERN_WEIGHT)

                if ml_confidence == "phishing" and "ML:Phishing" not in category:
                    category = f"{category}/ML:Phishing" if category != "Safe" else "ML:Phishing"

                reasoning = f"{reasoning}. ML confidence: {ml_confidence} ({ml_score:.1f}%)"
                return combined_threat, category, reasoning
        except Exception as e:
            logger.warning("ML inference failed in analyzer: %s", e)

        return base_threat, category, reasoning

    @classmethod
    async def analyze_threat(
        cls,
        email_body: str,
        sender: str,
        links: List[str],
        use_ml: bool = DEFAULT_ML_ENABLED,
    ) -> ThreatAnalysis:
        """
        Analyse email for threat indicators using structured pipeline stages.

        Args:
            email_body: Email body text.
            sender: Sender email address.
            links: List of URLs in the email.
            use_ml: Whether to attempt ML enhancement.

        Returns:
            ThreatAnalysis object.
        """
        body_lower = (email_body or "").lower()
        sender_lower = (sender or "").lower()
        links = links or []

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
            flagged_phrases=deduped_flags[:MAX_FLAGGED_PHRASES],
        )
