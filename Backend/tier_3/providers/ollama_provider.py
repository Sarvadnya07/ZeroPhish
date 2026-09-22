"""
Ollama Provider Adapter for Tier 3
==================================
Implements AIProvider for local Ollama instances (/api/chat) using httpx.
Operates fully locally without external network dependencies when active.
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


class OllamaProvider(AIProvider):
    """
    Adapter for local Ollama server running locally.
    Enables zero-data-leakage on-premise inference.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        raw_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self._base_url = raw_url.rstrip("/")
        self._model_name = model_name or os.getenv("T3_OLLAMA_MODEL", "llama3.2")

        self._enabled = enabled

        self._capabilities = ProviderCapabilities(
            provider_id="ollama",
            display_name="Ollama Local LLM",
            text_analysis=True,
            structured_json=True,
            vision=False,
            streaming=False,
            tool_calling=False,
            max_context_tokens=8192,
            max_output_tokens=2048,
            local=True,
            estimated_latency_ms=2500,
            requires_auth=False,
            supported_models=[self._model_name],
        )

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def is_available(self) -> bool:
        """
        Return True only if explicitly enabled. Unconfigured local services
        must report is_available() == False.
        """
        if self._enabled is not None:
            return self._enabled
        return os.getenv("OLLAMA_ENABLED", "false").lower() in ("true", "1", "yes")

    async def health_check(self) -> bool:
        """Probe Ollama server version endpoint."""
        if not self._enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                res = await client.get(f"{self._base_url}/api/version")
                return res.status_code == 200
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
                provider_id="ollama",
                model=self._model_name,
                status=ProviderExecutionStatus.UNAVAILABLE,
                error_message="Ollama local provider is not enabled (set OLLAMA_ENABLED=true).",
            )

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model_name,
            "messages": messages,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.0,
            },
        }

        endpoint = f"{self._base_url}/api/chat"

        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                response = await client.post(endpoint, json=payload)
                latency_ms = (time.perf_counter() - start_t) * 1000.0

                if response.status_code != 200:
                    return ProviderRawResponse(
                        provider_id="ollama",
                        model=self._model_name,
                        status=ProviderExecutionStatus.PROVIDER_ERROR,
                        latency_ms=latency_ms,
                        http_status_code=response.status_code,
                        error_message=f"Ollama returned HTTP {response.status_code}: {response.text[:200]}",
                    )

                data = response.json()
                content = data.get("message", {}).get("content", "")
                if not content or not content.strip():
                    return ProviderRawResponse(
                        provider_id="ollama",
                        model=self._model_name,
                        status=ProviderExecutionStatus.INVALID_PAYLOAD,
                        latency_ms=latency_ms,
                        error_message="Empty message content returned by Ollama.",
                    )

                return ProviderRawResponse(
                    provider_id="ollama",
                    model=self._model_name,
                    status=ProviderExecutionStatus.SUCCESS,
                    raw_text=content,
                    latency_ms=latency_ms,
                    http_status_code=200,
                )

        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id="ollama",
                model=self._model_name,
                status=ProviderExecutionStatus.TIMEOUT,
                latency_ms=latency_ms,
                error_message=f"Ollama request timed out after {timeout_sec}s",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            return ProviderRawResponse(
                provider_id="ollama",
                model=self._model_name,
                status=ProviderExecutionStatus.PROVIDER_ERROR,
                latency_ms=latency_ms,
                error_message=f"Ollama transport error: {e}",
            )
