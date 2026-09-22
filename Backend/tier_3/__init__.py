"""
Tier 3: Semantic AI Brain for Zero-Day Phishing Detection
=========================================================
Provider-agnostic AI architecture supporting Google Gemini,
OpenAI-compatible APIs, and local Ollama inference.

Exports:
    T3Result: Pydantic model for analysis result.
    T3Service: Main service facade.
    analyze_email_intent: Async function to analyze an email.
    get_t3_service: Get the global service instance.
    get_t3_router: Get the global capability router.
    Tier3Router: Router managing provider selection and fallbacks.
    AIProvider: Base class for custom providers.
    ProviderCapabilities: Explicit capability declarations.
    GeminiProvider: Google Gemini adapter.
    OpenAICompatibleProvider: OpenAI-compatible endpoint adapter.
    OllamaProvider: Local Ollama adapter.
"""

from tier_3.base import AIProvider, ProviderCapabilities, ProviderExecutionStatus, ProviderRawResponse
from tier_3.main import T3Result, T3Service, analyze_email_intent, get_t3_router, get_t3_service
from tier_3.providers.gemini_provider import GeminiProvider
from tier_3.providers.ollama_provider import OllamaProvider
from tier_3.providers.openai_provider import OpenAICompatibleProvider
from tier_3.router import Tier3Router
from tier_3.validator import (
    AI_FAILURE_CATEGORIES,
    ALLOWED_AI_CATEGORIES,
    LEGITIMATE_AI_CATEGORIES,
    ground_flagged_phrases,
    validate_and_normalize_response,
)

__all__ = [
    "T3Result",
    "T3Service",
    "analyze_email_intent",
    "get_t3_service",
    "get_t3_router",
    "Tier3Router",
    "AIProvider",
    "ProviderCapabilities",
    "ProviderExecutionStatus",
    "ProviderRawResponse",
    "GeminiProvider",
    "OpenAICompatibleProvider",
    "OllamaProvider",
    "LEGITIMATE_AI_CATEGORIES",
    "AI_FAILURE_CATEGORIES",
    "ALLOWED_AI_CATEGORIES",
    "ground_flagged_phrases",
    "validate_and_normalize_response",
]