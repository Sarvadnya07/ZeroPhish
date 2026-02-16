"""
Gateway Circuit Breaker Wrapper
Wraps execute_tier3 with circuit breaker protection
"""

import asyncio
from typing import Callable
from tier_3.main import analyze_email_intent
from models.gateway_models import Tier3Result
import os
import time

# This will be imported by gateway.py
async def execute_tier3_with_circuit_breaker(
    body: str,
    circuit_breaker,
    tier3_timeout: int
) -> Tier3Result:
    """Execute Tier 3 with circuit breaker protection."""
    start_time = time.time()

    # Define the actual Tier 3 execution logic
    async def _tier3_execution(body: str) -> Tier3Result:
        try:
            # Check if Gemini API key is configured
            if (
                not os.getenv("GEMINI_API_KEY")
                or os.getenv("GEMINI_API_KEY") == "your_actual_gemini_api_key_here"
            ):
                # This is not a failure, just unavailable
                raise ValueError("Gemini API key not configured")

            # Execute AI analysis with timeout
            result = await asyncio.wait_for(
                analyze_email_intent(body), timeout=tier3_timeout
            )

            execution_time = (time.time() - start_time) * 1000

            return Tier3Result(
                score=int(result.threat_score),
                category=result.category,
                reasoning=result.reasoning,
                flagged_phrases=result.flagged_phrases,
                status="complete",
                execution_time_ms=execution_time,
            )

        except asyncio.TimeoutError:
            # Timeout is a failure
            raise
        except ValueError as e:
            # API not configured - return neutral score, don't count as failure
            return Tier3Result(
                score=50,
                category="AI Unavailable",
                reasoning=str(e),
                flagged_phrases=[],
                status="unavailable",
                execution_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            # Other errors are failures
            raise

    # Define fallback for when circuit is open
    async def _tier3_fallback(body: str) -> Tier3Result:
        return Tier3Result(
            score=50,
            category="Circuit Open",
            reasoning="Tier 3 temporarily unavailable (circuit breaker open)",
            flagged_phrases=[],
            status="circuit_open",
            execution_time_ms=0,
        )

    # Use circuit breaker if provided
    if circuit_breaker:
        try:
            return await circuit_breaker.call(
                _tier3_execution, body, fallback=_tier3_fallback
            )
        except Exception as e:
            # If circuit breaker call fails, use fallback
            print(f"Circuit breaker error: {e}")
            return await _tier3_fallback(body)
    else:
        # No circuit breaker, execute directly with error handling
        try:
            return await _tier3_execution(body)
        except asyncio.TimeoutError:
            return Tier3Result(
                score=50,
                category="Timeout",
                reasoning="AI analysis timed out",
                flagged_phrases=[],
                status="timeout",
                execution_time_ms=tier3_timeout * 1000,
            )
        except Exception as e:
            return Tier3Result(
                score=50,
                category="Error",
                reasoning=f"AI analysis failed: {str(e)}",
                flagged_phrases=[],
                status="failed",
                execution_time_ms=(time.time() - start_time) * 1000,
            )
