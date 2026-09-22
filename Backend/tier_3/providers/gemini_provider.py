"""
Gemini Provider Adapter for Tier 3
==================================
Implements AIProvider for Google Gemini using google-generativeai.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import google.generativeai as genai

from ..base import AIProvider, ProviderCapabilities, ProviderExecutionStatus, ProviderRawResponse

logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """
    Adapter for Google Gemini models via google.generativeai SDK.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> None:
        self._explicit_key = api_key
        self._model_name = model_name or os.getenv("T3_GEMINI_MODEL", "gemini-1.5-flash")
        self._model = None
        self._capabilities = ProviderCapabilities(
            provider_id="gemini",
            display_name="Google Gemini",
            text_analysis=True,
            structured_json=True,
            vision=True,
            streaming=True,
            tool_calling=True,
            max_context_tokens=1048576,
            max_output_tokens=8192,
            local=False,
            estimated_latency_ms=1200,
            requires_auth=True,
            supported_models=["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash-exp"],
        )

        key = self._get_api_key()
        if key:
            try:
                genai.configure(api_key=key)
                self._model = genai.GenerativeModel(model_name=self._model_name)
                logger.info("GeminiProvider initialized with model: %s", self._model_name)
            except Exception as e:
                logger.error("Failed to initialize GeminiProvider: %s", e)
                self._model = None

    def _get_api_key(self) -> Optional[str]:
        if self._explicit_key is not None:
            return self._explicit_key
        return os.getenv("GEMINI_API_KEY")

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def is_available(self) -> bool:
        key = self._get_api_key()
        return bool(key and key.strip())

    async def health_check(self) -> bool:
        return self.is_available()

    async def generate_analysis(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        timeout_sec: float = 2.5,
        **kwargs: Any,
    ) -> ProviderRawResponse:
        start_t = time.perf_counter()

        if not self.is_available():
            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.UNAVAILABLE,
                error_message="Gemini API key is not configured or model failed initialization.",
            )

        active_key = self._get_api_key()
        if self._model is None and active_key:
            try:
                genai.configure(api_key=active_key)
                self._model = genai.GenerativeModel(model_name=self._model_name)
            except Exception as e:
                logger.error("Failed to initialize Gemini model: %s", e)
                return ProviderRawResponse(
                    provider_id="gemini",
                    model=self._model_name,
                    status=ProviderExecutionStatus.PROVIDER_ERROR,
                    error_message=f"Gemini initialization error: {e}",
                )

        try:
            # Re-create or wrap with system_instruction if provided
            active_model = self._model
            if system_instruction:
                active_model = genai.GenerativeModel(
                    model_name=self._model_name,
                    system_instruction=system_instruction,
                )

            response = await asyncio.wait_for(
                asyncio.to_thread(
                    active_model.generate_content,
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                        temperature=0.0,
                        max_output_tokens=500,
                    ),
                ),
                timeout=timeout_sec,
            )

            latency_ms = (time.perf_counter() - start_t) * 1000.0

            if not response or not response.text:
                return ProviderRawResponse(
                    provider_id="gemini",
                    model=self._model_name,
                    status=ProviderExecutionStatus.INVALID_PAYLOAD,
                    latency_ms=latency_ms,
                    error_message="Gemini returned empty response text.",
                )

            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.SUCCESS,
                raw_text=response.text,
                latency_ms=latency_ms,
            )

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.TIMEOUT,
                latency_ms=latency_ms,
                error_message=f"Gemini call timed out after {timeout_sec}s.",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            err_str = str(e).lower()
            if "quota" in err_str or "resourceexhausted" in err_str or "429" in err_str:
                status = ProviderExecutionStatus.RATE_LIMITED
            elif "401" in err_str or "403" in err_str or "api_key" in err_str or "unauthenticated" in err_str:
                status = ProviderExecutionStatus.AUTH_ERROR
            else:
                status = ProviderExecutionStatus.PROVIDER_ERROR

            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=status,
                latency_ms=latency_ms,
                error_message=f"Gemini execution error: {e}",
            )

    async def generate_multimodal_analysis(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str,
        system_instruction: Optional[str] = None,
        timeout_sec: float = 3.5,
        **kwargs: Any,
    ) -> ProviderRawResponse:
        start_t = time.perf_counter()

        if not self.is_available():
            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.UNAVAILABLE,
                error_message="Gemini API key is not configured or model failed initialization.",
            )

        active_key = self._get_api_key()
        if self._model is None and active_key:
            try:
                genai.configure(api_key=active_key)
                self._model = genai.GenerativeModel(model_name=self._model_name)
            except Exception as e:
                logger.error("Failed to initialize Gemini model: %s", e)
                return ProviderRawResponse(
                    provider_id="gemini",
                    model=self._model_name,
                    status=ProviderExecutionStatus.PROVIDER_ERROR,
                    error_message=f"Gemini initialization error: {e}",
                )

        try:
            active_model = self._model
            if system_instruction:
                active_model = genai.GenerativeModel(
                    model_name=self._model_name,
                    system_instruction=system_instruction,
                )

            image_part = {"mime_type": mime_type, "data": image_bytes}
            contents = [image_part, prompt]

            response = await asyncio.wait_for(
                asyncio.to_thread(
                    active_model.generate_content,
                    contents,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                        temperature=0.0,
                        max_output_tokens=1024,
                    ),
                ),
                timeout=timeout_sec,
            )

            latency_ms = (time.perf_counter() - start_t) * 1000.0

            if not response or not response.text:
                return ProviderRawResponse(
                    provider_id="gemini",
                    model=self._model_name,
                    status=ProviderExecutionStatus.INVALID_PAYLOAD,
                    latency_ms=latency_ms,
                    error_message="Gemini returned empty multimodal response text.",
                )

            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.SUCCESS,
                raw_text=response.text,
                latency_ms=latency_ms,
            )

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=ProviderExecutionStatus.TIMEOUT,
                latency_ms=latency_ms,
                error_message=f"Gemini multimodal call timed out after {timeout_sec}s.",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            err_str = str(e).lower()
            if "quota" in err_str or "resourceexhausted" in err_str or "429" in err_str:
                status = ProviderExecutionStatus.RATE_LIMITED
            elif "401" in err_str or "403" in err_str or "api_key" in err_str or "unauthenticated" in err_str:
                status = ProviderExecutionStatus.AUTH_ERROR
            else:
                status = ProviderExecutionStatus.PROVIDER_ERROR

            return ProviderRawResponse(
                provider_id="gemini",
                model=self._model_name,
                status=status,
                latency_ms=latency_ms,
                error_message=f"Gemini multimodal execution error: {e}",
            )
