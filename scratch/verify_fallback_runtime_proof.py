"""
Runtime Fallback Proof Script for Phase 1.5B
===========================================
Executes two end-to-end Gateway runtime scenarios:
Scenario 1: Primary fails -> Fallback succeeds -> Final provider metadata & verdict
Scenario 2: Primary fails -> All fallbacks fail -> Explicit Tier3 failure -> Partial score preserved
"""

import asyncio
import json
import os
import sys
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure Backend directory is in sys.path
sys.path.insert(0, os.path.abspath("Backend"))

from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    GatewayScanResponse,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    ThreatAnalysisDetail,
    Verdict,
)
from gateway_circuit_wrapper import execute_tier3_with_circuit_breaker
from gateway import _finalize_tier3, get_scan_result_repository
from tier_3.base import (
    AIProvider,
    ProviderCapabilities,
    ProviderExecutionStatus,
    ProviderRawResponse,
)
from tier_3.main import get_t3_router, T3Service
from tier_3.router import Tier3Router


class ConfigurableTestProvider(AIProvider):
    def __init__(
        self,
        provider_id: str,
        status: ProviderExecutionStatus,
        raw_text: Optional[str] = None,
        error_msg: Optional[str] = None,
    ):
        self._provider_id = provider_id
        self._status = status
        self._raw_text = raw_text
        self._error_msg = error_msg
        self._capabilities = ProviderCapabilities(
            provider_id=provider_id,
            display_name=f"Provider {provider_id}",
            supported_models=[f"{provider_id}-v1"],
        )
        self.invocation_count = 0

    @property
    def capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def is_available(self) -> bool:
        return True

    async def health_check(self) -> bool:
        return True

    async def generate_analysis(self, prompt: str, **kwargs) -> ProviderRawResponse:
        self.invocation_count += 1
        return ProviderRawResponse(
            provider_id=self._provider_id,
            model=f"{self._provider_id}-v1",
            status=self._status,
            raw_text=self._raw_text,
            error_message=self._error_msg,
        )


async def run_scenario_1():
    print("\n========================================================")
    print("SCENARIO 1: Primary Provider Fails -> Fallback Succeeds")
    print("========================================================")

    # Setup Router with Primary (Fails) and Fallback (Succeeds)
    router = Tier3Router(primary_provider="gemini_primary", fallback_providers=["openai_fallback"])

    primary_fail = ConfigurableTestProvider(
        provider_id="gemini_primary",
        status=ProviderExecutionStatus.TIMEOUT,
        error_msg="Gemini upstream latency exceeded 2.5s",
    )
    fallback_success = ConfigurableTestProvider(
        provider_id="openai_fallback",
        status=ProviderExecutionStatus.SUCCESS,
        raw_text=json.dumps({
            "threat_score": 85.0,
            "category": "Credential",
            "reasoning": "Detected credential harvesting attempt in password reset request",
            "flagged_phrases": ["reset password"],
            "requires_visual_check": True,
            "confidence": 0.94,
        }),
    )

    router.register_provider("gemini_primary", primary_fail)
    router.register_provider("openai_fallback", fallback_success)

    import tier_3.main as t3_main
    t3_main._t3_service = T3Service(router=router)

    # Execute through circuit breaker
    with patch("gateway_circuit_wrapper.get_t3_router", return_value=router), \
         patch("tier_3.main.get_t3_router", return_value=router):
        
        t3_result = await execute_tier3_with_circuit_breaker(
            body="Please reset password immediately or account locked.",
            circuit_breaker=None,
            tier3_timeout=3,
            sender="admin@notice-auth.com",
            subject="Urgent Security Notice",
        )

    print(f"Primary Provider: gemini_primary (Invocations: {primary_fail.invocation_count})")
    print(f"Primary Failure Reason: {primary_fail._error_msg}")
    print(f"Fallback Provider: openai_fallback (Invocations: {fallback_success.invocation_count})")
    print(f"Fallback Execution Result: Status={t3_result.status}, Category={t3_result.category}, Score={t3_result.score}")
    print(f"Final Provider Metadata: Provider={t3_result.provider}, Model={t3_result.model}")

    # Now execute Gateway finalization with partial SUSPICIOUS
    scan_id = "scan_scenario_1"
    existing_scan = GatewayScanResponse(
        scan_id=scan_id,
        partial_score=45.0,
        final_score=None,
        verdict=Verdict.SUSPICIOUS,
        tier1=Tier1Result(score=40, status=CleanStatus.SUSPICIOUS),
        tier2=Tier2Result(
            score=45.0,
            domain_analysis=DomainAnalysis(status=DomainStatus.OK, score=20.0),
            threat_analysis=Tier2Analysis(status=DomainStatus.SUSPICIOUS, score=45.0),
            threat_details=ThreatAnalysisDetail(threat_level=45, category="Test", reasoning="Reason"),
        ),
    )

    mock_repo = MagicMock()
    mock_repo.get = AsyncMock(return_value=existing_scan)
    mock_repo.save = AsyncMock()

    with patch("gateway.get_scan_result_repository", return_value=mock_repo), \
         patch("gateway.execute_tier3_with_circuit_breaker", AsyncMock(return_value=t3_result)):
        await _finalize_tier3(scan_id, "email body")

    finalized_response = mock_repo.save.call_args[0][1]
    print(f"Gateway Final Score: {finalized_response.final_score}")
    print(f"Gateway Final Verdict: {finalized_response.verdict}")
    assert finalized_response.tier3.provider == "openai_fallback"
    assert finalized_response.tier3.model == "openai_fallback-v1"
    assert finalized_response.verdict in (Verdict.SUSPICIOUS, Verdict.CRITICAL)
    print("SCENARIO 1 RESULT: SUCCESS (Fallback executed, metadata verified)")
    return {
        "primary_provider": "gemini_primary",
        "primary_failure": "Gemini upstream latency exceeded 2.5s",
        "fallback_provider": "openai_fallback",
        "fallback_model": t3_result.model,
        "fallback_score": t3_result.score,
        "final_verdict": str(finalized_response.verdict),
    }


async def run_scenario_2():
    print("\n========================================================")
    print("SCENARIO 2: Primary Fails -> All Fallbacks Fail -> Partial Preserved")
    print("========================================================")

    router = Tier3Router(
        primary_provider="gemini_primary",
        fallback_providers=["openai_fb1", "ollama_fb2"],
    )

    p1 = ConfigurableTestProvider("gemini_primary", ProviderExecutionStatus.TIMEOUT, error_msg="Timeout 2.5s")
    p2 = ConfigurableTestProvider("openai_fb1", ProviderExecutionStatus.RATE_LIMITED, error_msg="HTTP 429 Quota")
    p3 = ConfigurableTestProvider("ollama_fb2", ProviderExecutionStatus.UNAVAILABLE, error_msg="Daemon offline")

    router.register_provider("gemini_primary", p1)
    router.register_provider("openai_fb1", p2)
    router.register_provider("ollama_fb2", p3)

    import tier_3.main as t3_main
    t3_main._t3_service = T3Service(router=router)

    with patch("gateway_circuit_wrapper.get_t3_router", return_value=router), \
         patch("tier_3.main.get_t3_router", return_value=router):
        
        t3_result = await execute_tier3_with_circuit_breaker(
            body="Suspicious invoice attached",
            circuit_breaker=None,
            tier3_timeout=3,
        )

    print(f"Primary Invocations: {p1.invocation_count}")
    print(f"Fallback 1 Invocations: {p2.invocation_count}")
    print(f"Fallback 2 Invocations: {p3.invocation_count}")
    print(f"All-Fail Result: Status={t3_result.status}, Category={t3_result.category}, Score={t3_result.score}")

    # Finalize with partial CRITICAL (82.5)
    scan_id = "scan_scenario_2"
    existing_scan = GatewayScanResponse(
        scan_id=scan_id,
        partial_score=82.5,
        final_score=None,
        verdict=Verdict.CRITICAL,
        tier1=Tier1Result(score=80, status=CleanStatus.SUSPICIOUS),
        tier2=Tier2Result(
            score=85.0,
            domain_analysis=DomainAnalysis(status=DomainStatus.SUSPICIOUS, score=85.0),
            threat_analysis=Tier2Analysis(status=DomainStatus.SUSPICIOUS, score=85.0),
            threat_details=ThreatAnalysisDetail(threat_level=85, category="Phish", reasoning="Bad"),
        ),
    )

    mock_repo = MagicMock()
    mock_repo.get = AsyncMock(return_value=existing_scan)
    mock_repo.save = AsyncMock()

    with patch("gateway.get_scan_result_repository", return_value=mock_repo), \
         patch("gateway.execute_tier3_with_circuit_breaker", AsyncMock(return_value=t3_result)):
        await _finalize_tier3(scan_id, "email body")

    finalized = mock_repo.save.call_args[0][1]
    print(f"Initial Partial Score: 82.5 (Verdict: CRITICAL)")
    print(f"Final Score after all AI providers failed: {finalized.final_score}")
    print(f"Final Verdict after all AI providers failed: {finalized.verdict}")
    assert finalized.final_score == 82.5, f"Score was mutated! {finalized.final_score} != 82.5"
    assert finalized.verdict == Verdict.CRITICAL
    print("SCENARIO 2 RESULT: SUCCESS (Score 82.5 and CRITICAL preserved identically)")
    return {
        "all_providers_failed": True,
        "tier3_category": t3_result.category,
        "initial_partial_score": 82.5,
        "final_score": finalized.final_score,
        "final_verdict": str(finalized.verdict),
    }


async def main():
    s1 = await run_scenario_1()
    s2 = await run_scenario_2()
    with open("scratch/fallback_runtime_proof.json", "w") as f:
        json.dump({"scenario_1": s1, "scenario_2": s2}, f, indent=2)
    print("\nBOTH RUNTIME PROOF SCENARIOS EXECUTED SUCCESSFULLY.")


if __name__ == "__main__":
    asyncio.run(main())
