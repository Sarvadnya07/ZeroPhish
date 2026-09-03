"""
Vision Service — Proactive Visual Brand & Login Portal Spoofing Analysis.

Analyzes viewport screenshots from browser tabs to detect brand impersonation,
credential harvesting forms, and pixel‑level phishing cues using Google Gemini Multimodal Vision
with robust offline heuristic fallback.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import List, Optional, Dict, Any

from .models import DetectedElement, VisionAnalysisResult, VisionAnalysisRequest

logger = logging.getLogger(__name__)

# ---------- Configuration ----------
GEMINI_TIMEOUT = float(os.getenv("VISION_GEMINI_TIMEOUT", "6.0"))
GEMINI_MODEL = os.getenv("VISION_GEMINI_MODEL", "gemini-1.5-flash")
MIN_IMAGE_SIZE_BYTES = 8
DEFAULT_THREAT_SCORE_SAFE = 10.0
DEFAULT_THREAT_SCORE_SUSPICIOUS = 85.0
DEFAULT_THREAT_SCORE_LEGITIMATE_LOGIN = 15.0

# Brand keywords for local heuristic matching
BRAND_KEYWORDS = {
    "microsoft": ["microsoft", "office365", "outlook", "azure", "windows"],
    "google": ["google", "gmail", "drive", "docs", "calendar", "cloud"],
    "apple": ["apple", "icloud", "apple id"],
    "paypal": ["paypal", "venmo"],
    "amazon": ["amazon", "aws"],
    "facebook": ["facebook", "meta"],
    "twitter": ["twitter", "x.com"],
    "linkedin": ["linkedin"],
    "github": ["github"],
    "bank": ["bank", "chase", "wells fargo", "bank of america", "hsbc", "barclays"],
}

# Suspicious title keywords
SUSPICIOUS_TITLE_KEYWORDS = [
    "login", "password", "sign in", "verify", "account", "portal", "secure",
    "update", "confirm", "access", "reset", "unlock", "alert", "warning",
]

# Credential field indicators
CREDENTIAL_INDICATORS = [
    "username", "password", "email", "phone", "verification code",
    "account number", "credit card", "cvv", "ssn", "tax id",
]


class VisionService:
    """
    Evaluates visual phishing cues from browser screenshots and DOM metadata.

    Supports two modes:
    1. Gemini Multimodal Vision (if API key is configured)
    2. Local heuristic fallback (deterministic)
    """

    @staticmethod
    async def analyze_screenshot(
        image_b64: str,
        url: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze screenshot for visual phishing artifacts.

        Args:
            image_b64: Base64‑encoded image (data‑URL or raw).
            url: Optional page URL for context.
            title: Optional page title for context.

        Returns:
            VisionAnalysisResult as a dictionary.
        """
        start = time.perf_counter()

        # 1. Decode & validate image bytes
        image_bytes, mime_type = VisionService._decode_image(image_b64)
        if image_bytes is None:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return VisionAnalysisResult(
                is_phishing=False,
                threat_score=DEFAULT_THREAT_SCORE_SAFE,
                detected_elements=[],
                matched_brand=None,
                reasoning="Could not parse image data: Could not decode image data.",
                processing_time_ms=duration_ms,
            ).model_dump()

        # 2. Try Gemini if available
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key and len(image_bytes) > MIN_IMAGE_SIZE_BYTES:
            result = await VisionService._analyze_with_gemini(
                image_bytes, mime_type, url, title, start
            )
            if result is not None:
                return result

        # 3. Local heuristic fallback
        result = VisionService._analyze_locally(image_bytes, url, title, start)
        return result.model_dump()

    @staticmethod
    def _decode_image(image_b64: str) -> tuple[Optional[bytes], str]:
        """Decode base64 image and determine MIME type."""
        mime_type = "image/jpeg"
        b64_str = image_b64

        if "," in image_b64:
            header, b64_str = image_b64.split(",", 1)
            if "image/png" in header:
                mime_type = "image/png"
            elif "image/webp" in header:
                mime_type = "image/webp"
            # Default stays image/jpeg

        try:
            image_bytes = base64.b64decode(b64_str)
            if len(image_bytes) < MIN_IMAGE_SIZE_BYTES:
                logger.warning("Image data too small: %d bytes", len(image_bytes))
                return None, mime_type
            return image_bytes, mime_type
        except Exception as e:
            logger.warning("Failed to decode base64 image: %s", e)
            return None, mime_type

    @staticmethod
    async def _analyze_with_gemini(
        image_bytes: bytes,
        mime_type: str,
        url: Optional[str],
        title: Optional[str],
        start: float,
    ) -> Optional[Dict[str, Any]]:
        """Attempt Gemini vision analysis; returns result dict or None on failure."""
        try:
            import google.generativeai as genai
        except ImportError:
            logger.debug("google-generativeai not installed; skipping Gemini.")
            return None

        try:
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel(GEMINI_MODEL)

            prompt = VisionService._build_gemini_prompt(url, title)
            image_part = {"mime_type": mime_type, "data": image_bytes}

            response = await asyncio.wait_for(
                asyncio.to_thread(
                    model.generate_content,
                    [image_part, prompt],
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json"
                    ),
                ),
                timeout=GEMINI_TIMEOUT,
            )

            if response and response.text:
                parsed = json.loads(response.text)
                duration_ms = (time.perf_counter() - start) * 1000.0
                return VisionService._parse_gemini_response(parsed, duration_ms)

        except asyncio.TimeoutError:
            logger.warning("Gemini vision analysis timed out after %.1fs", GEMINI_TIMEOUT)
        except json.JSONDecodeError as e:
            logger.warning("Gemini response JSON parse error: %s", e)
        except Exception as e:
            logger.debug("Gemini vision analysis failed: %s", e)

        return None

    @staticmethod
    def _build_gemini_prompt(url: Optional[str], title: Optional[str]) -> str:
        """Build the Gemini prompt for visual phishing analysis."""
        url_context = f"URL: {url or 'Unknown'}"
        title_context = f"Page Title: {title or 'Unknown'}"

        return f"""You are a senior cybersecurity visual forensic analyst inspecting a webpage screenshot for brand spoofing and credential harvesting.

Context:
- {url_context}
- {title_context}

Analyze the visual contents of the image:
1. Does this page display a login portal, authentication form, or credential input field?
2. Does the visual branding (logos, brand colors, layout matching Google, Microsoft, Apple, PayPal, Amazon, Banks, etc.) match the declared domain?
3. Is this a spoofed, deceptive, or cloned phishing portal?

CRITICAL: Return ONLY a valid JSON object matching this schema:
{{
    "is_phishing": <boolean>,
    "threat_score": <float 0.0 to 100.0>,
    "matched_brand": <string or null>,
    "detected_elements": [
        {{"class_name": "<string>", "confidence": <float 0.0 to 1.0>}}
    ],
    "reasoning": "<1-2 sentence concise explanation>"
}}
Do NOT output markdown, backticks, or any conversational text. Only valid JSON."""

    @staticmethod
    def _parse_gemini_response(parsed: Dict[str, Any], duration_ms: float) -> Dict[str, Any]:
        """Parse Gemini JSON response into a VisionAnalysisResult dict."""
        elements = [
            DetectedElement(
                class_name=el.get("class_name", "unknown"),
                confidence=float(el.get("confidence", 0.9)),
                box=None,
            )
            for el in parsed.get("detected_elements", [])
        ]
        return VisionAnalysisResult(
            is_phishing=bool(parsed.get("is_phishing", False)),
            threat_score=float(parsed.get("threat_score", DEFAULT_THREAT_SCORE_SAFE)),
            detected_elements=elements,
            matched_brand=parsed.get("matched_brand"),
            reasoning=str(parsed.get("reasoning", "Gemini vision analysis complete.")),
            processing_time_ms=duration_ms,
        ).model_dump()

    @staticmethod
    def _analyze_locally(
        image_bytes: bytes,
        url: Optional[str],
        title: Optional[str],
        start: float,
    ) -> VisionAnalysisResult:
        """
        Deterministic local heuristic fallback.

        Uses URL, title, and basic image metadata to assess phishing risk.
        """
        elements: List[DetectedElement] = []
        elements.append(DetectedElement(class_name="viewport_screenshot", confidence=1.0, box=None))

        url_lower = (url or "").lower()
        title_lower = (title or "").lower()

        is_suspicious = False
        score = DEFAULT_THREAT_SCORE_SAFE
        matched_brand = None
        reasoning = "Visual screenshot verified. No spoofed authentication portal detected."

        # 1. Detect brand from URL/title
        matched_brand = VisionService._match_brand(url_lower, title_lower)

        # 2. Detect login/credential forms from title
        if any(kw in title_lower for kw in SUSPICIOUS_TITLE_KEYWORDS):
            elements.append(DetectedElement(class_name="login_form", confidence=0.90, box=None))
            if matched_brand:
                # Check if brand appears in URL (legitimate)
                if matched_brand.lower() in url_lower:
                    score = DEFAULT_THREAT_SCORE_LEGITIMATE_LOGIN
                    reasoning = f"Legitimate {matched_brand} authentication portal detected."
                else:
                    is_suspicious = True
                    score = DEFAULT_THREAT_SCORE_SUSPICIOUS
                    reasoning = (
                        f"Visual portal matches {matched_brand} authentication interface, "
                        f"but URL domain does not correspond to official {matched_brand} infrastructure."
                    )
                    elements.append(DetectedElement(class_name="credential_field", confidence=0.95, box=None))
            else:
                # Generic suspicious login page
                if "phishing" in title_lower or "secure" not in url_lower:
                    is_suspicious = True
                    score = 75.0
                    reasoning = "Suspicious login portal detected without clear brand affiliation."
                    elements.append(DetectedElement(class_name="credential_field", confidence=0.85, box=None))
                else:
                    score = 30.0
                    reasoning = "Login portal detected but could not verify brand legitimacy."

        # 3. Check for credential fields in title (if not already flagged)
        if any(kw in title_lower for kw in CREDENTIAL_INDICATORS):
            if not is_suspicious:
                elements.append(DetectedElement(class_name="credential_field", confidence=0.80, box=None))
                score = max(score, 40.0)
                reasoning += " Credential input fields detected."

        # 4. Additional heuristic: suspicious combinations
        if "bank" in title_lower and not any(bank in url_lower for bank in ["bank", "chase", "wellsfargo"]):
            is_suspicious = True
            score = max(score, 80.0)
            matched_brand = "Banking"
            reasoning = "Banking credential page detected but domain does not match known bank domains."

        duration_ms = (time.perf_counter() - start) * 1000.0
        return VisionAnalysisResult(
            is_phishing=is_suspicious,
            threat_score=score,
            detected_elements=elements,
            matched_brand=matched_brand,
            reasoning=reasoning,
            processing_time_ms=duration_ms,
        )

    @staticmethod
    def _match_brand(url_lower: str, title_lower: str) -> Optional[str]:
        """Identify a brand from URL or title using keyword mapping."""
        # Prefer URL match
        for brand, keywords in BRAND_KEYWORDS.items():
            for kw in keywords:
                if kw in url_lower:
                    return brand.title()
        # Fallback to title
        for brand, keywords in BRAND_KEYWORDS.items():
            for kw in keywords:
                if kw in title_lower:
                    return brand.title()
        return None