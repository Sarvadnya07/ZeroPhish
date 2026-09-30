"""
Controlled In-Process Test Provider for Tier 3 Runtime Verification
===================================================================
Enables deterministic integration testing of the Gateway runtime and lifecycle
without making external LLM network calls. Only active when explicitly enabled
via environment configuration (ZEROPHISH_ENABLE_TEST_PROVIDER=true).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

from ..base import AIProvider, ProviderCapabilities, ProviderExecutionStatus, ProviderRawResponse

logger = logging.getLogger(__name__)


class ControlledTestProvider(AIProvider):
    """
    Controlled deterministic provider for testing Gateway runtime pipelines.
    Configurable via environment variables or prompt inspection.
    """

    def __init__(self) -> None:
        self._capabilities = ProviderCapabilities(
            provider_id="test_provider",
            display_name="Controlled Test Provider",
            text_analysis=True,
            structured_json=True,
            vision=True,
            streaming=False,
            tool_calling=False,
            max_context_tokens=32768,
            max_output_tokens=2048,
            local=True,
            estimated_latency_ms=10,
            requires_auth=False,
            supported_models=["controlled-test-model"],
        )

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def is_available(self) -> bool:
        return os.getenv("ZEROPHISH_ENABLE_TEST_PROVIDER", "false").lower() in ("true", "1", "yes")

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
                provider_id="test_provider",
                model="controlled-test-model",
                status=ProviderExecutionStatus.UNAVAILABLE,
                error_message="Test provider is not enabled.",
            )

        # Check for simulated failure mode (via env or payload prompt marker)
        sim_failure = os.getenv("ZEROPHISH_TEST_T3_FAILURE")
        if sim_failure == "timeout" or "SIMULATE_T3_TIMEOUT" in prompt:
            return ProviderRawResponse(
                provider_id="test_provider",
                model="controlled-test-model",
                status=ProviderExecutionStatus.TIMEOUT,
                error_message="Simulated test provider timeout.",
            )
        elif sim_failure == "error" or "SIMULATE_T3_FAILURE" in prompt or "direct deposit setup could not be verified" in prompt.lower() or "unauthorized access detected from ip 192.168.1.1" in prompt.lower():
            return ProviderRawResponse(
                provider_id="test_provider",
                model="controlled-test-model",
                status=ProviderExecutionStatus.PROVIDER_ERROR,
                error_message="Simulated test provider failure.",
            )

        # By default, check prompt/body markers or environment variable
        # If prompt contains "VISUAL_CHECK_REQUIRED" or email subject/body matches visual test:
        req_visual = False
        if "VISUAL_CHECK_REQUIRED" in prompt or "login portal requires optical brand inspection" in prompt.lower() or "requires_visual_check" in prompt:
            req_visual = True

        # Extract score / category defaults
        score = 45.0 if req_visual else 15.0
        category = "Credential" if req_visual else "Safe"
        reasoning = (
            "Login portal detected requiring visual optical verification."
            if req_visual
            else "Routine benign communication."
        )

        response_payload = {
            "threat_score": score,
            "category": category,
            "reasoning": reasoning,
            "flagged_phrases": ["sign in", "login"] if req_visual else [],
            "requires_visual_check": req_visual,
            "confidence": 0.85 if req_visual else 0.95,
        }

        latency_ms = (time.perf_counter() - start_t) * 1000.0
        return ProviderRawResponse(
            provider_id="test_provider",
            model="controlled-test-model",
            status=ProviderExecutionStatus.SUCCESS,
            raw_text=json.dumps(response_payload),
            latency_ms=latency_ms,
            http_status_code=200,
        )
