"""
Tier 3: Semantic AI Brain for Zero‑Day Phishing Detection

This module provides Gemini‑powered semantic analysis to catch sophisticated
phishing and social engineering attacks that traditional rules (T1) and
technical metadata (T2) cannot detect.

It uses Google Gemini 1.5 Flash with a strict system prompt and JSON‑mode
enforcement to classify email intent, detect BEC/CEO fraud, and flag
visual verification needs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

import google.generativeai as genai
from pydantic import BaseModel, Field, ValidationError

# ---------- Configuration ----------
logger = logging.getLogger(__name__)

# Environment variables with sensible defaults
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("T3_GEMINI_MODEL", "gemini-1.5-flash")
T3_TIMEOUT_SEC = float(os.getenv("T3_TIMEOUT_SEC", "2.5"))
T3_MAX_RETRIES = int(os.getenv("T3_MAX_RETRIES", "2"))
T3_RETRY_BACKOFF = float(os.getenv("T3_RETRY_BACKOFF", "1.0"))
T3_FALLBACK_SCORE = float(os.getenv("T3_FALLBACK_SCORE", "50.0"))

# ---------- Pydantic Models ----------
class T3Result(BaseModel):
    """
    Tier 3 Semantic AI Analysis Result.

    Attributes:
        threat_score: Weighted AI score from 0.0 to 100.0.
        category: One of: BEC, CEO_Fraud, Financial, Urgency, Credential,
                  Impersonation, Safe, AI_UNAVAILABLE.
        reasoning: Brief user‑friendly explanation of threat assessment.
        flagged_phrases: Email snippets that triggered alarm.
        requires_visual_check: True if the payload warrants pixel‑by‑pixel visual verification.
    """
    threat_score: float = Field(..., ge=0.0, le=100.0)
    category: str = Field(..., description="Threat category")
    reasoning: str = Field(..., description="Explanation of assessment")
    flagged_phrases: list[str] = Field(default_factory=list)
    requires_visual_check: bool = Field(default=False)

    class Config:
        extra = "forbid"  # Reject unexpected fields


# ---------- Service Class ----------
class T3Service:
    """
    Tier 3 Semantic AI Service using Google Gemini.

    Provides asynchronous analysis of email bodies for phishing/social engineering.

    Attributes:
        model: Gemini GenerativeModel instance.
        timeout_sec: Maximum time for a single analysis call.
        max_retries: Number of retry attempts on transient failures.
    """

    SYSTEM_INSTRUCTION = """You are a Forensic Cybersecurity Analyst specializing in Zero‑Day phishing, CEO Fraud, and Business Email Compromise (BEC) detection.

Analyze the provided email for malicious intent markers:
- **Business Email Compromise (BEC)**: "Are you at your desk?", "I need a quick favor", or unnatural hierarchical requests.
- **CEO Fraud**: Executive tone mismatches, directing wire transfers or payroll diversions.
- **Synthetic Urgency**: "Discount ends tonight", "Account suspended", "Immediate action required".
- **Credential Harvesting**: "Update password", "Re‑authenticate", "Secure your account".
- **Impersonation**: Spoofed authority figures or trusted vendors.

CRITICAL: You MUST return ONLY a valid JSON object matching this exact schema:
{
    "threat_score": <float 0‑100>,
    "category": "<BEC|CEO_Fraud|Financial|Urgency|Credential|Impersonation|Safe>",
    "reasoning": "<1‑sentence explanation focusing on the psychological manipulation detected>",
    "flagged_phrases": ["<snippet1>", "<snippet2>"],
    "requires_visual_check": <boolean, true ONLY if the email directs to a high‑value portal (e.g., Bank, Microsoft, Apple, AWS) requiring clone detection>
}

Do NOT include markdown, code blocks, explanations, or conversational text. ONLY JSON."""

    def __init__(self) -> None:
        self.timeout_sec = T3_TIMEOUT_SEC
        self.max_retries = T3_MAX_RETRIES
        self._initialized = False
        self._model = None

        if not GEMINI_API_KEY:
            logger.critical("GEMINI_API_KEY environment variable is not set. Tier 3 will be unavailable.")
            return

        try:
            genai.configure(api_key=GEMINI_API_KEY)
            self._model = genai.GenerativeModel(
                model_name=GEMINI_MODEL,
                system_instruction=self.SYSTEM_INSTRUCTION,
            )
            self._initialized = True
            logger.info("T3Service initialized with model: %s, timeout: %.1fs", GEMINI_MODEL, self.timeout_sec)
        except Exception as e:
            logger.error("Failed to initialize T3Service: %s", e, exc_info=True)
            self._initialized = False

    def is_available(self) -> bool:
        """Return True if the service is ready to perform analysis."""
        return self._initialized

    async def analyze_email_intent(self, email_body: str) -> T3Result:
        """
        Analyze email for semantic phishing/social engineering markers.

        Args:
            email_body: Full email text to analyze.

        Returns:
            T3Result with threat assessment and flagged content.

        Raises:
            ValueError: If the service is not initialized.
        """
        if not self._initialized:
            logger.error("T3Service not initialized; cannot analyze.")
            raise ValueError("Tier 3 service is unavailable (API key missing or init failed).")

        if not email_body or not email_body.strip():
            return T3Result(
                threat_score=0.0,
                category="Safe",
                reasoning="Email body is empty.",
                flagged_phrases=[],
                requires_visual_check=False,
            )

        # Truncate long emails to avoid token limits (Gemini 1.5 Flash has 1M context, but keep reasonable)
        max_len = 50000  # ~50k chars is safe
        if len(email_body) > max_len:
            email_body = email_body[:max_len] + "\n...[TRUNCATED]"
            logger.debug("Email body truncated to %d chars", max_len)

        prompt = f"Analyze this email for malicious intent and social engineering:\n\n---EMAIL---\n{email_body}\n---END---"

        for attempt in range(1, self.max_retries + 1):
            try:
                result = await self._call_gemini_with_timeout(prompt)
                if result is not None:
                    return result
                logger.warning("Gemini returned invalid response, attempt %d/%d", attempt, self.max_retries)
            except asyncio.TimeoutError:
                logger.warning("Gemini timeout, attempt %d/%d", attempt, self.max_retries)
            except Exception as e:
                logger.warning("Gemini error, attempt %d/%d: %s", attempt, self.max_retries, e)

            # Backoff before retry
            if attempt < self.max_retries:
                await asyncio.sleep(T3_RETRY_BACKOFF * (2 ** (attempt - 1)))

        # All retries exhausted
        logger.error("Tier 3 analysis failed after %d attempts. Returning fallback.", self.max_retries)
        return T3Result(
            threat_score=T3_FALLBACK_SCORE,
            category="AI_UNAVAILABLE",
            reasoning="Semantic analysis unavailable after multiple attempts. Escalate to human review if T2 is high.",
            flagged_phrases=[],
            requires_visual_check=False,
        )

    async def _call_gemini_with_timeout(self, prompt: str) -> Optional[T3Result]:
        """
        Call Gemini with a timeout and parse the JSON response.

        Returns:
            T3Result on success, None on failure.
        """
        if self._model is None:
            logger.warning("Gemini model is not initialized")
            return None

        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._model.generate_content,
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                        temperature=0.0,  # Deterministic output
                    ),
                ),
                timeout=self.timeout_sec,
            )

            if not response or not response.text:
                logger.warning("Gemini returned empty response")
                return None

            # Parse JSON
            data = json.loads(response.text)

            # Validate against Pydantic model
            result = T3Result(**data)
            logger.debug("Gemini analysis successful: score=%.1f, category=%s",
                         result.threat_score, result.category)
            return result

        except json.JSONDecodeError as e:
            logger.warning("Gemini returned invalid JSON: %s", e)
            logger.debug("Raw response: %s", response.text[:200] if response and response.text else "None")
            return None
        except ValidationError as e:
            logger.warning("Gemini response schema validation failed: %s", e)
            return None
        except Exception as e:
            logger.warning("Gemini call exception: %s", e)
            raise  # Re-raise to be handled by retry loop


# ---------- Global Instance & Helpers ----------
_t3_service: Optional[T3Service] = None


def get_t3_service() -> T3Service:
    """Get or initialize the Tier 3 service singleton."""
    global _t3_service
    if _t3_service is None:
        _t3_service = T3Service()
    return _t3_service


async def analyze_email_intent(email_body: str) -> T3Result:
    """
    Public async wrapper for email intent analysis.

    Returns a T3Result; uses the global T3Service instance.
    """
    service = get_t3_service()
    return await service.analyze_email_intent(email_body)