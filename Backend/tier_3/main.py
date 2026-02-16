from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import google.generativeai as genai
from pydantic import BaseModel, Field


class T3Result(BaseModel):
    """Tier 3 Semantic AI Analysis Result."""

    threat_score: float = Field(
        ..., ge=0.0, le=100.0, description="Weighted AI score from 0.0 to 100.0"
    )
    category: str = Field(
        ..., description="One of: Financial, Urgency, Credential, Safe, AI_UNAVAILABLE"
    )
    reasoning: str = Field(..., description="Brief user-friendly explanation of threat assessment")
    flagged_phrases: list[str] = Field(
        default_factory=list, description="Email snippets that triggered alarm"
    )


class T3Service:
    """Tier 3: Semantic AI Brain using Gemini for Zero-Day Detection."""

    SYSTEM_INSTRUCTION = """You are a Forensic Cybersecurity Analyst specializing in Zero-Day phishing and social engineering detection.

Analyze the provided email for malicious intent markers:
- Urgency/Time Pressure: "Act now", "Urgent", "Immediate action required"
- Financial/Authority Pressure: "Verify payment", "Confirm identity", "Account locked"
- Credential Harvesting: "Update password", "Re-authenticate", "Verify credentials"
- Impersonation: Fake executive/authority sender patterns
- Psychological Manipulation: Fear tactics, fake urgency, false authority

CRITICAL: You MUST return ONLY a valid JSON object matching this exact schema:
{
    "threat_score": <float 0-100>,
    "category": "<Financial|Urgency|Credential|Impersonation|Safe>",
    "reasoning": "<1-sentence explanation>",
    "flagged_phrases": ["<snippet1>", "<snippet2>"]
}

Do NOT include markdown, code blocks, explanations, or conversational text. ONLY JSON."""

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key or api_key == "your_actual_gemini_api_key_here":
            raise ValueError(
                "GEMINI_API_KEY not set in .env file. Please add your actual Gemini API key."
            )

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name="gemini-1.5-flash", system_instruction=self.SYSTEM_INSTRUCTION
        )
        self.timeout_sec = 2.5  # Leave buffer for orchestration

    async def analyze_email_intent(self, email_body: str) -> T3Result:
        """
        Analyze email for semantic phishing/social engineering markers.

        Args:
            email_body: Full email text to analyze

        Returns:
            T3Result with threat assessment and flagged content

        Fallback: Returns neutral/warning state if AI analysis fails
        """
        if not email_body or not email_body.strip():
            return T3Result(
                threat_score=0.0,
                category="Safe",
                reasoning="Email body is empty.",
                flagged_phrases=[],
            )

        prompt = f"""Analyze this email for malicious intent and social engineering:

---EMAIL---
{email_body}
---END---"""

        try:
            # Use JSON mode to guarantee valid schema output
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.model.generate_content,
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json"
                    ),
                ),
                timeout=self.timeout_sec,
            )

            if not response or not response.text:
                raise ValueError("Empty response from model")

            # Parse JSON response
            data = json.loads(response.text)
            return T3Result(**data)

        except asyncio.TimeoutError:
            # AI took too long - return neutral assessment
            return T3Result(
                threat_score=25.0,
                category="AI_UNAVAILABLE",
                reasoning="AI analysis timeout. Escalate to human review if high T2 score.",
                flagged_phrases=["[timeout]"],
            )

        except json.JSONDecodeError as e:
            # AI response malformed - return warning
            return T3Result(
                threat_score=35.0,
                category="AI_UNAVAILABLE",
                reasoning="AI response parsing failed. Check email content validity.",
                flagged_phrases=["[parse_error]"],
            )

        except Exception as e:
            # Catch-all fallback: API key invalid, network error, etc.
            return T3Result(
                threat_score=50.0,
                category="AI_UNAVAILABLE",
                reasoning=f"Deep semantic scan failed: {type(e).__name__}. Technical metadata (T2) takes priority.",
                flagged_phrases=[],
            )


# Global instance
_t3_service: T3Service | None = None


def get_t3_service() -> T3Service:
    """Get or initialize the Tier 3 service."""
    global _t3_service
    if _t3_service is None:
        _t3_service = T3Service()
    return _t3_service


async def analyze_email_intent(email_body: str) -> T3Result:
    """Public async wrapper for email intent analysis."""
    service = get_t3_service()
    return await service.analyze_email_intent(email_body)
