"""
Gateway Circuit Breaker Wrapper

Wraps execute_tier3 with circuit breaker protection.
Provides structured error handling, logging, and fallback responses.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Optional, Protocol

from models.gateway_models import Tier3Result, TierStatus
from tier_3.main import analyze_email_intent

logger = logging.getLogger(__name__)


class CircuitBreakerProtocol(Protocol):
    """Protocol for circuit breaker with call method."""
    async def call(
        self,
        func: Callable[..., Any],
        *args: Any,
        fallback: Optional[Callable[..., Any]] = None,
        **kwargs: Any
    ) -> Any:
        """Execute function with circuit breaker protection."""
        ...


def _coerce_tier_status(value: str | TierStatus) -> TierStatus:
    """Normalize a tier status into the Enum type expected by Tier3Result."""
    if isinstance(value, TierStatus):
        return value

    try:
        return TierStatus(value)
    except ValueError:
        normalized = value.strip().lower().replace(" ", "_")
        for member in TierStatus:
            if member.value == normalized:
                return member
        return TierStatus.FAILED


class Tier3ExecutionError(Exception):
    """Raised when Tier 3 execution fails for a non‑configuration reason."""
    pass


class Tier3UnavailableError(Exception):
    """Raised when Tier 3 is unavailable (e.g., missing API key)."""
    pass


async def execute_tier3_with_circuit_breaker(
    body: str,
    circuit_breaker: Optional[CircuitBreakerProtocol],
    tier3_timeout: int,
) -> Tier3Result:
    """
    Execute Tier 3 with circuit breaker protection.

    Args:
        body: Email body text to analyse.
        circuit_breaker: CircuitBreaker instance (or None).
        tier3_timeout: Timeout in seconds for the AI call.

    Returns:
        Tier3Result with status (complete, timeout, unavailable, circuit_open, failed).
    """
    start_time = time.perf_counter()

    # Define the actual Tier 3 execution logic
    async def _tier3_execution(text: str) -> Tier3Result:
        # Check if Gemini API key is configured
        if not os.getenv("GEMINI_API_KEY"):
            logger.warning("Gemini API key not configured; Tier 3 unavailable.")
            raise Tier3UnavailableError("Gemini API key not configured")

        try:
            # Execute AI analysis with timeout
            result = await asyncio.wait_for(
                analyze_email_intent(text),
                timeout=tier3_timeout
            )

            execution_ms = (time.perf_counter() - start_time) * 1000.0

            return Tier3Result(
                score=int(result.threat_score),
                category=result.category,
                reasoning=result.reasoning,
                flagged_phrases=result.flagged_phrases,
                confidence=float(getattr(result, "confidence", 1.0)),
                status=_coerce_tier_status("complete"),
                execution_time_ms=execution_ms,
            )

        except asyncio.TimeoutError as e:
            logger.warning("Tier 3 execution timed out after %ss", tier3_timeout)
            raise Tier3ExecutionError(f"Timeout: {e}") from e
        except Tier3UnavailableError:
            # Re-raise as-is so caller can handle with neutral fallback
            raise
        except Exception as e:
            logger.error("Tier 3 execution failed: %s", e, exc_info=True)
            raise Tier3ExecutionError(f"Execution error: {e}") from e

    # Define fallback for when circuit is open or execution fails
    async def _tier3_fallback(
        text: str,
        reason: str = "Circuit open or execution failed",
        status: str | TierStatus = "circuit_open",
    ) -> Tier3Result:
        logger.info("Tier 3 fallback triggered: %s", reason)
        return Tier3Result(
            score=50,
            category="AI Unavailable",
            reasoning=reason,
            flagged_phrases=[],
            confidence=0.0,
            status=_coerce_tier_status(status),
            execution_time_ms=0.0,
        )

    # Execute with circuit breaker if provided
    if circuit_breaker:
        try:
            return await circuit_breaker.call(
                _tier3_execution,
                body,
                fallback=_tier3_fallback,
            )
        except Tier3UnavailableError:
            # API key missing – return neutral score without counting as failure
            return await _tier3_fallback(body, reason="Gemini API key not configured", status="unavailable")
        except Tier3ExecutionError as e:
            # Circuit breaker will already have handled fallback, but if it didn't,
            # we provide a final neutral score.
            logger.warning("Tier 3 execution error after circuit breaker: %s", e)
            return await _tier3_fallback(body, reason=str(e), status="failed")
        except Exception as e:
            # Unexpected error – fallback
            logger.error("Unexpected error in circuit breaker call: %s", e, exc_info=True)
            return await _tier3_fallback(body, reason=f"Unexpected error: {e}", status="error")
    else:
        # No circuit breaker – execute directly with error handling
        try:
            return await _tier3_execution(body)
        except Tier3UnavailableError:
            return await _tier3_fallback(body, reason="Gemini API key not configured", status="unavailable")
        except asyncio.TimeoutError:
            return await _tier3_fallback(
                body,
                reason=f"AI analysis timed out after {tier3_timeout}s",
                status="timeout"
            )
        except Tier3ExecutionError as e:
            return await _tier3_fallback(body, reason=str(e), status="failed")
        except Exception as e:
            logger.error("Unhandled error in Tier 3: %s", e, exc_info=True)
            return await _tier3_fallback(body, reason=f"Unexpected error: {e}", status="error")