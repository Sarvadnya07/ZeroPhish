"""
Tier 3 Canonical Response Validator & Evidence Grounding
========================================================
Implements a strict, centralized validation pipeline for all raw AI provider outputs.
Ensures:
- Verbatim evidence grounding against untrusted input
- Defense against prompt injection / format poisoning
- Rejection of unexpected extra fields
- Rejection of invalid categories (NEVER defaults to Safe)
- Numeric sanity checking (NaN, Inf, range bounds)
- Consistent attribution of provider, model, and failure categories
"""

from __future__ import annotations

import json
import logging
import math
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, ValidationError

from .base import ProviderExecutionStatus, ProviderRawResponse

logger = logging.getLogger(__name__)

LEGITIMATE_AI_CATEGORIES: Set[str] = {
    "BEC",
    "CEO_Fraud",
    "Financial",
    "Urgency",
    "Credential",
    "Impersonation",
    "Safe",
    "Suspicious",
    "Malicious",
}

AI_FAILURE_CATEGORIES: Set[str] = {
    "AI_UNAVAILABLE",
    "AI_TIMEOUT",
    "AI_RATE_LIMITED",
    "AI_PROVIDER_ERROR",
    "AI_INVALID_RESPONSE",
}

ALLOWED_AI_CATEGORIES: Set[str] = LEGITIMATE_AI_CATEGORIES | AI_FAILURE_CATEGORIES


class T3Result(BaseModel):
    """
    Tier 3 Canonical Semantic AI Analysis Result.
    """
    threat_score: float = Field(..., ge=0.0, le=100.0)
    category: str = Field(..., description="Threat category")
    reasoning: str = Field(..., min_length=1, max_length=1000, description="Explanation of assessment")
    flagged_phrases: List[str] = Field(default_factory=list, max_length=20)
    requires_visual_check: bool = Field(default=False)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provider: Optional[str] = Field(default=None, description="Provider identifier that produced result")
    model: Optional[str] = Field(default=None, description="Specific model utilized")
    error_category: Optional[str] = Field(default=None, description="Explicit error category if failed")

    class Config:
        extra = "forbid"  # Forbid unexpected fields on the final result object


class _LLMExpectedPayload(BaseModel):
    """
    Strict intermediate validator for untrusted LLM output payloads.
    Directly forbids any extra keys or attacker-injected fields.
    """
    threat_score: float = Field(..., ge=0.0, le=100.0)
    category: str = Field(...)
    reasoning: str = Field(..., min_length=1, max_length=1000)
    flagged_phrases: List[str] = Field(default_factory=list, max_length=20)
    requires_visual_check: bool = Field(default=False)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    class Config:
        extra = "forbid"


def ground_flagged_phrases(raw_phrases: List[str], full_text: str) -> List[str]:
    """
    Ground model-flagged phrases against actual input text to suppress hallucinations.
    Only phrases that are verbatim case-insensitive substrings of the email body are preserved.
    """
    if not full_text:
        return []
    text_lower = full_text.lower()
    grounded: List[str] = []
    for phrase in raw_phrases:
        cleaned = phrase.strip()
        if not cleaned:
            continue
        if cleaned.lower() in text_lower:
            grounded.append(cleaned)
        else:
            logger.debug("Filtered ungrounded AI phrase hallucination: %s", cleaned)
    return grounded[:10]


def strip_markdown_fences(text: str) -> str:
    """Strip markdown code block delimiters if returned by provider."""
    raw = text.strip()
    if raw.startswith("```json"):
        raw = raw[7:]
    elif raw.startswith("```"):
        raw = raw[3:]
    if raw.endswith("```"):
        raw = raw[:-3]
    return raw.strip()


def validate_and_normalize_response(
    raw_resp: ProviderRawResponse,
    original_body: str,
    fallback_score: float = 50.0,
) -> T3Result:
    """
    Execute canonical validation pipeline on raw provider output.
    Returns guaranteed T3Result; on any validation failure, returns explicit
    failure category (AI_INVALID_RESPONSE, AI_TIMEOUT, etc.) with fallback score.
    """
    provider_id = raw_resp.provider_id
    model_name = raw_resp.model

    # 1. Transport/Execution status check
    if raw_resp.status != ProviderExecutionStatus.SUCCESS:
        cat_map = {
            ProviderExecutionStatus.TIMEOUT: "AI_TIMEOUT",
            ProviderExecutionStatus.RATE_LIMITED: "AI_RATE_LIMITED",
            ProviderExecutionStatus.UNAVAILABLE: "AI_UNAVAILABLE",
            ProviderExecutionStatus.AUTH_ERROR: "AI_PROVIDER_ERROR",
            ProviderExecutionStatus.PROVIDER_ERROR: "AI_PROVIDER_ERROR",
            ProviderExecutionStatus.INVALID_PAYLOAD: "AI_INVALID_RESPONSE",
        }
        err_cat = cat_map.get(raw_resp.status, "AI_PROVIDER_ERROR")
        err_reason = raw_resp.error_message or f"Provider execution failed with status: {raw_resp.status.value}"
        return T3Result(
            threat_score=fallback_score,
            category=err_cat,
            reasoning=f"Semantic analysis failed ({err_cat}): {err_reason}",
            flagged_phrases=[],
            requires_visual_check=False,
            confidence=0.0,
            provider=provider_id,
            model=model_name,
            error_category=err_cat,
        )

    # 2. Extract and sanitize raw text or dictionary
    raw_data: Optional[Dict[str, Any]] = raw_resp.raw_json
    if raw_data is None:
        if not raw_resp.raw_text or not raw_resp.raw_text.strip():
            return _build_invalid_response(
                "Provider returned empty response text.",
                provider_id, model_name, fallback_score
            )
        cleaned_text = strip_markdown_fences(raw_resp.raw_text)
        try:
            raw_data = json.loads(cleaned_text)
        except json.JSONDecodeError as e:
            return _build_invalid_response(
                f"Malformed JSON: {e}",
                provider_id, model_name, fallback_score
            )

    if not isinstance(raw_data, dict):
        return _build_invalid_response(
            "Provider returned non-object JSON.",
            provider_id, model_name, fallback_score
        )

    # 3. Category validation (Strict whitelist, never defaults to Safe)
    cat = str(raw_data.get("category", "")).strip()
    if not cat or cat not in LEGITIMATE_AI_CATEGORIES:
        return _build_invalid_response(
            f"Invalid threat category returned by AI: '{cat}'",
            provider_id, model_name, fallback_score
        )

    # 4. threat_score validation (Numeric, non-NaN/Inf, bounded [0, 100])
    if "threat_score" not in raw_data or raw_data["threat_score"] is None:
        return _build_invalid_response(
            "Missing required field: 'threat_score'",
            provider_id, model_name, fallback_score
        )
    try:
        score_val = float(raw_data["threat_score"])
        if math.isnan(score_val) or math.isinf(score_val) or score_val < 0.0 or score_val > 100.0:
            return _build_invalid_response(
                f"'threat_score' out of bounds [0, 100]: {score_val}",
                provider_id, model_name, fallback_score
            )
        raw_data["threat_score"] = score_val
    except (ValueError, TypeError) as e:
        return _build_invalid_response(
            f"Invalid 'threat_score': {e}",
            provider_id, model_name, fallback_score
        )

    # 5. confidence validation (Numeric, non-NaN/Inf, bounded [0.0, 1.0])
    if "confidence" in raw_data and raw_data["confidence"] is not None:
        try:
            conf_val = float(raw_data["confidence"])
            if math.isnan(conf_val) or math.isinf(conf_val) or conf_val < 0.0 or conf_val > 1.0:
                return _build_invalid_response(
                    f"'confidence' out of bounds [0.0, 1.0]: {conf_val}",
                    provider_id, model_name, fallback_score
                )
            raw_data["confidence"] = conf_val
        except (ValueError, TypeError) as e:
            return _build_invalid_response(
                f"Invalid 'confidence': {e}",
                provider_id, model_name, fallback_score
            )

    # 6. requires_visual_check validation (boolean or int 0/1)
    if "requires_visual_check" in raw_data and raw_data["requires_visual_check"] is not None:
        if not isinstance(raw_data["requires_visual_check"], (bool, int)):
            return _build_invalid_response(
                "'requires_visual_check' must be a boolean",
                provider_id, model_name, fallback_score
            )
        raw_data["requires_visual_check"] = bool(raw_data["requires_visual_check"])

    # 7. reasoning validation (non-empty string)
    reasoning = raw_data.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        return _build_invalid_response(
            "Missing or empty 'reasoning' field",
            provider_id, model_name, fallback_score
        )

    # 8. Ground flagged phrases against original body
    raw_phrases = raw_data.get("flagged_phrases", [])
    if isinstance(raw_phrases, list):
        raw_data["flagged_phrases"] = ground_flagged_phrases(raw_phrases, original_body)
    elif raw_phrases is not None:
        return _build_invalid_response(
            "'flagged_phrases' must be a list of strings",
            provider_id, model_name, fallback_score
        )

    # 9. Intermediate payload validation (strictly forbids unknown extra fields)
    try:
        validated_llm = _LLMExpectedPayload(**raw_data)
    except ValidationError as e:
        return _build_invalid_response(
            f"Schema validation error: {e}",
            provider_id, model_name, fallback_score
        )

    # 10. Construct canonical T3Result with provider attribution
    return T3Result(
        threat_score=validated_llm.threat_score,
        category=validated_llm.category,
        reasoning=validated_llm.reasoning,
        flagged_phrases=validated_llm.flagged_phrases,
        requires_visual_check=validated_llm.requires_visual_check,
        confidence=validated_llm.confidence,
        provider=provider_id,
        model=model_name,
        error_category=None,
    )


def _build_invalid_response(
    reason: str,
    provider_id: str,
    model_name: str,
    fallback_score: float,
) -> T3Result:
    """Helper to return standardized AI_INVALID_RESPONSE result."""
    return T3Result(
        threat_score=fallback_score,
        category="AI_INVALID_RESPONSE",
        reasoning=f"Semantic analysis failed (AI_INVALID_RESPONSE): {reason}",
        flagged_phrases=[],
        requires_visual_check=False,
        confidence=0.0,
        provider=provider_id,
        model=model_name,
        error_category="AI_INVALID_RESPONSE",
    )
