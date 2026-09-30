"""
OpenAI-Compatible Provider Adapter for Tier 3
=============================================
Implements AIProvider for OpenAI, Groq, OpenRouter, and other OpenAI-compatible
chat completion endpoints using httpx.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import httpx

from ..base import AIProvider, ProviderCapabilities, ProviderExecutionStatus, ProviderRawResponse

logger = logging.getLogger(__name__)


class OpenAICompatibleProvider(AIProvider):
    """
    Adapter for OpenAI-compatible REST APIs (/v1/chat/completions).
    Compatible with OpenAI, Groq, OpenRouter, Together, vLLM, etc.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        provider_id: str = "openai_compatible",
        display_name: str = "OpenAI-Compatible API",
        supports_vision: bool = False,
    ) -> None:
        self._explicit_key = api_key
        raw_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self._base_url = raw_url.rstrip("/")
        self._model_name = model_name or os.getenv("T3_OPENAI_MODEL", "gpt-4o-mini")
        self._provider_id = provider_id
        self._display_name = display_name
        self._capabilities = ProviderCapabilities(
            provider_id=self._provider_id,
            display_name=self._display_name,
            text_analysis=True,
            structured_json=True,
            vision=supports_vision,
            streaming=True,
            tool_calling=True,
            max_context_tokens=128000,
            max_output_tokens=4096,
            local=False,
            estimated_latency_ms=900,
            requires_auth=True,
            supported_models=[self._model_name],
        )

    def _get_api_key(self) -> Optional[str]:
        if self._explicit_key is not None:
            return self._explicit_key
        return os.getenv("OPENAI_API_KEY")

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def is_available(self) -> bool:
        k = self._get_api_key()
        return bool(k and k.strip())

    async def health_check(self) -> bool:
        if not self.is_available():
            return False
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(
                    f"{self._base_url}/models",
                    headers={"Authorization": f"Bearer {self._get_api_key()}"},
                )
                return res.status_code in (200, 403, 404)
        except Exception:
            return False

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
                provider_id=self._provider_id,
                model=self._model_name,
                status=ProviderExecutionStatus.UNAVAILABLE,
                error_message="API key is not configured for OpenAI-compatible provider.",
            )

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model_name,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 500,
            "response_format": {"type": "json_object"},
        }

        endpoint = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._get_api_key()}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
                latency_ms = (time.perf_counter() - start_t) * 1000.0

                if response.status_code == 429:
                    return ProviderRawResponse(
                        provider_id=self._provider_id,
                        model=self._model_name,
                        status=ProviderExecutionStatus.RATE_LIMITED,
                        latency_ms=latency_ms,
                        http_status_code=429,
                        error_message="OpenAI rate limit / quota exceeded (HTTP 429)",
                    )
                elif response.status_code in (401, 403):
                    return ProviderRawResponse(
                        provider_id=self._provider_id,
                        model=self._model_name,
                        status=ProviderExecutionStatus.AUTH_ERROR,
                        latency_ms=latency_ms,
                        http_status_code=response.status_code,
                        error_message=f"Authentication failed (HTTP {response.status_code})",
                    )
                elif response.status_code != 200:
                    return ProviderRawResponse(
                        provider_id=self._provider_id,
                        model=self._model_name,
                        status=ProviderExecutionStatus.PROVIDER_ERROR,
                        latency_ms=latency_ms,
                        http_status_code=response.status_code,
                        error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                    )

                data = response.json()
                choices = data.get("choices", [])
                if not choices:
                    return ProviderRawResponse(
                        provider_id=self._provider_id,
                        model=self._model_name,
                        status=ProviderExecutionStatus.INVALID_PAYLOAD,
                        latency_ms=latency_ms,
                        error_message="Missing choices in response payload.",
                    )

                content = choices[0].get("message", {}).get("content", "")
                if not content or not content.strip():
                    return ProviderRawResponse(
                        provider_id=self._provider_id,
                        model=self._model_name,
                        status=ProviderExecutionStatus.INVALID_PAYLOAD,
                        latency_ms=latency_ms,
                        error_message="Empty message content in response.",
                    )

                return ProviderRawResponse(
                    provider_id=self._provider_id,
                    model=self._model_name,
                    status=ProviderExecutionStatus.SUCCESS,
                    raw_text=content,
                    latency_ms=latency_ms,
                    http_status_code=200,
                )

        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id=self._provider_id,
                model=self._model_name,
                status=ProviderExecutionStatus.TIMEOUT,
                latency_ms=latency_ms,
                error_message=f"Request timed out after {timeout_sec}s",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id=self._provider_id,
                model=self._model_name,
                status=ProviderExecutionStatus.PROVIDER_ERROR,
                latency_ms=latency_ms,
                error_message=f"Transport error: {e}",
            )
