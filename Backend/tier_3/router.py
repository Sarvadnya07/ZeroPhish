"""
Tier 3 Policy-Aware Provider Router & Fallback Chain
====================================================
Implements capability-based provider selection, priority ordering, and
resilient fallback execution.
Guarantees that untrusted AI computation cannot bypass security controls.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

from .base import AIProvider, ProviderExecutionStatus, ProviderRawResponse
from .prompt import SYSTEM_INSTRUCTION
from .providers.gemini_provider import GeminiProvider
from .providers.openai_provider import OpenAICompatibleProvider
from .providers.ollama_provider import OllamaProvider
from .validator import T3Result, validate_and_normalize_response

logger = logging.getLogger(__name__)


class Tier3Router:
    """
    Capability-aware router managing provider selection and fallback chains.
    """

    def __init__(
        self,
        primary_provider: Optional[str] = None,
        fallback_providers: Optional[List[str]] = None,
        timeout_sec: Optional[float] = None,
        fallback_score: float = 50.0,
    ) -> None:
        self.primary_provider = primary_provider or os.getenv("TIER3_PRIMARY_PROVIDER", "gemini")
        if fallback_providers is not None:
            self.fallback_providers = fallback_providers
        else:
            raw_fallbacks = os.getenv("TIER3_FALLBACK_PROVIDERS", "openai_compatible,ollama")
            self.fallback_providers = [p.strip() for p in raw_fallbacks.split(",") if p.strip()]

        self.timeout_sec = timeout_sec or float(os.getenv("T3_TIMEOUT_SEC", "2.5"))
        self.fallback_score = fallback_score or float(os.getenv("T3_FALLBACK_SCORE", "50.0"))

        self._providers: Dict[str, AIProvider] = {}
        self._register_default_providers()

    def _register_default_providers(self) -> None:
        """Instantiate and register standard default providers."""
        self.register_provider("gemini", GeminiProvider())
        self.register_provider("openai_compatible", OpenAICompatibleProvider())
        self.register_provider("ollama", OllamaProvider())

    def register_provider(self, provider_id: str, provider: AIProvider) -> None:
        """Register or overwrite an AI provider instance."""
        self._providers[provider_id] = provider
        logger.debug("Registered Tier 3 provider: %s", provider_id)

    def get_provider(self, provider_id: str) -> Optional[AIProvider]:
        """Retrieve registered provider by ID."""
        return self._providers.get(provider_id)

    def has_available_provider(self, require_vision: bool = False) -> bool:
        """
        Return True if at least one eligible provider has credentials/running service.
        """
        for provider_id in self._get_execution_order():
            provider = self._providers.get(provider_id)
            if not provider or not provider.is_available():
                continue
            if require_vision and not provider.capabilities.vision:
                continue
            return True
        return False

    def get_available_providers(self) -> List[str]:
        """List provider IDs that are currently available."""
        return [
            pid for pid in self._get_execution_order()
            if self._providers.get(pid) and self._providers[pid].is_available()
        ]

    def _get_execution_order(self) -> List[str]:
        """Return ordered list of provider IDs (primary first, then fallbacks)."""
        order = [self.primary_provider]
        for fb in self.fallback_providers:
            if fb not in order:
                order.append(fb)
        return order

    async def route_and_execute(
        self,
        prompt: str,
        original_body: str,
        system_instruction: Optional[str] = None,
        require_vision: bool = False,
        timeout_sec: Optional[float] = None,
    ) -> T3Result:
        """
        Execute analysis following the provider fallback chain.
        Ensures strict fail-safe behavior: on total failure, returns an explicit
        error category with fallback score (50.0) and 0.0 confidence.
        """
        active_timeout = timeout_sec or self.timeout_sec
        sys_inst = system_instruction or SYSTEM_INSTRUCTION
        execution_order = self._get_execution_order()

        last_error_status: ProviderExecutionStatus = ProviderExecutionStatus.UNAVAILABLE
        last_error_msg: str = "No configured Tier 3 providers are available."
        last_provider_id: str = self.primary_provider
        last_model_name: str = "none"

        attempted_count = 0

        for provider_id in execution_order:
            provider = self._providers.get(provider_id)
            if not provider:
                continue

            # Check capability requirement
            if require_vision and not provider.capabilities.vision:
                logger.debug("Skipping provider %s (does not satisfy vision requirement)", provider_id)
                continue

            # Check availability
            if not provider.is_available():
                logger.debug("Provider %s is not available (credentials/service missing)", provider_id)
                continue

            attempted_count += 1
            last_provider_id = provider_id
            last_model_name = provider.capabilities.supported_models[0] if provider.capabilities.supported_models else provider_id

            logger.info("Executing Tier 3 analysis via provider: %s (model: %s)", provider_id, last_model_name)

            try:
                raw_resp = await provider.generate_analysis(
                    prompt=prompt,
                    system_instruction=sys_inst,
                    timeout_sec=active_timeout,
                )
            except Exception as e:
                logger.error("Unhandled exception from provider %s: %s", provider_id, e, exc_info=True)
                raw_resp = ProviderRawResponse(
                    provider_id=provider_id,
                    model=last_model_name,
                    status=ProviderExecutionStatus.PROVIDER_ERROR,
                    error_message=f"Unhandled provider exception: {e}",
                )

            # If execution succeeded, validate against canonical schema
            if raw_resp.status == ProviderExecutionStatus.SUCCESS:
                validated_result = validate_and_normalize_response(
                    raw_resp=raw_resp,
                    original_body=original_body,
                    fallback_score=self.fallback_score,
                )
                # If valid and not an AI_INVALID_RESPONSE error category, return immediately
                if validated_result.category not in ("AI_INVALID_RESPONSE", "AI_PROVIDER_ERROR"):
                    return validated_result

                # Schema or validation failure: record and attempt fallback if available
                logger.warning(
                    "Provider %s produced invalid response (%s): %s",
                    provider_id, validated_result.category, validated_result.reasoning
                )
                last_error_status = ProviderExecutionStatus.INVALID_PAYLOAD
                last_error_msg = validated_result.reasoning
                last_provider_id = provider_id
                last_model_name = raw_resp.model
                continue

            # Provider failed (timeout, rate-limit, auth, network)
            logger.warning(
                "Provider %s failed with status %s: %s",
                provider_id, raw_resp.status.value, raw_resp.error_message
            )
            last_error_status = raw_resp.status
            last_error_msg = raw_resp.error_message or f"Execution failed ({raw_resp.status.value})"
            last_provider_id = provider_id
            last_model_name = raw_resp.model

        # Fallback chain exhausted or no provider was available
        if attempted_count == 0:
            last_error_status = ProviderExecutionStatus.UNAVAILABLE
            last_error_msg = "No eligible AI provider is configured or available."

        synth_raw = ProviderRawResponse(
            provider_id=last_provider_id,
            model=last_model_name,
            status=last_error_status,
            error_message=last_error_msg,
        )
        return validate_and_normalize_response(
            raw_resp=synth_raw,
            original_body=original_body,
            fallback_score=self.fallback_score,
        )

    async def route_and_execute_multimodal(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str,
        system_instruction: Optional[str] = None,
        timeout_sec: Optional[float] = None,
    ) -> ProviderRawResponse:
        """
        Execute multimodal vision analysis following the provider fallback chain.
        Filters strictly for providers declaring capabilities.vision == True.
        Returns normalized ProviderRawResponse.
        """
        active_timeout = timeout_sec or self.timeout_sec
        execution_order = self._get_execution_order()

        last_error_status: ProviderExecutionStatus = ProviderExecutionStatus.UNAVAILABLE
        last_error_msg: str = "No configured vision-capable AI providers are available."
        last_provider_id: str = self.primary_provider
        last_model_name: str = "none"

        attempted_count = 0

        for provider_id in execution_order:
            provider = self._providers.get(provider_id)
            if not provider:
                continue

            # Check capability requirement: must have vision
            if not provider.capabilities.vision:
                logger.debug("Skipping provider %s (does not declare vision capability)", provider_id)
                continue

            if not provider.is_available():
                logger.debug("Vision provider %s is not available (credentials/service missing)", provider_id)
                continue

            attempted_count += 1
            last_provider_id = provider_id
            last_model_name = (
                provider.capabilities.supported_models[0]
                if provider.capabilities.supported_models
                else provider_id
            )

            logger.info(
                "Executing multimodal vision analysis via provider: %s (model: %s)",
                provider_id,
                last_model_name,
            )

            try:
                raw_resp = await provider.generate_multimodal_analysis(
                    prompt=prompt,
                    image_bytes=image_bytes,
                    mime_type=mime_type,
                    system_instruction=system_instruction,
                    timeout_sec=active_timeout,
                )
            except Exception as e:
                logger.error("Unhandled exception from vision provider %s: %s", provider_id, e, exc_info=True)
                raw_resp = ProviderRawResponse(
                    provider_id=provider_id,
                    model=last_model_name,
                    status=ProviderExecutionStatus.PROVIDER_ERROR,
                    error_message=f"Unhandled provider exception: {e}",
                )

            if raw_resp.status == ProviderExecutionStatus.SUCCESS:
                return raw_resp

            logger.warning(
                "Vision provider %s failed with status %s: %s",
                provider_id,
                raw_resp.status.value,
                raw_resp.error_message,
            )
            last_error_status = raw_resp.status
            last_error_msg = raw_resp.error_message or f"Vision execution failed ({raw_resp.status.value})"
            last_provider_id = provider_id
            last_model_name = raw_resp.model

        if attempted_count == 0:
            last_error_status = ProviderExecutionStatus.UNAVAILABLE
            last_error_msg = "No eligible vision-capable AI provider is configured or available."

        return ProviderRawResponse(
            provider_id=last_provider_id,
            model=last_model_name,
            status=last_error_status,
            error_message=last_error_msg,
        )
