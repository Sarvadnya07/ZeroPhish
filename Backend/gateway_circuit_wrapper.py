"""
Gateway Circuit Breaker Wrapper

Wraps execute_tier3 with circuit breaker protection.
Provides structured error handling, logging, and fallback responses.
Preserves explicit failure states and propagates visual verification needs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Optional, Protocol

from models.gateway_models import Tier3Result, TierStatus
from tier_3.main import analyze_email_intent, get_t3_router

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
    sender: Optional[str] = None,
    subject: Optional[str] = None,
) -> Tier3Result:
    """
    Execute Tier 3 with circuit breaker protection.

    Args:
        body: Email body text to analyze.
        circuit_breaker: CircuitBreaker instance (or None).
        tier3_timeout: Timeout in seconds for the AI call.
        sender: Optional sender address / header.
        subject: Optional email subject line.

    Returns:
        Tier3Result with status (complete, timeout, unavailable, failed).
    """
    start_time = time.perf_counter()

    # Define the actual Tier 3 execution logic
    async def _tier3_execution(
        text: str,
        sender_val: Optional[str] = None,
        subject_val: Optional[str] = None,
    ) -> Tier3Result:
        # Check if any Tier 3 AI provider is configured and available
        router = get_t3_router()
        if not router.has_available_provider():
            logger.warning("No Tier 3 AI provider configured or available.")
            raise Tier3UnavailableError("No Tier 3 AI provider configured or available")

        try:
            # Execute AI analysis with timeout
            result = await asyncio.wait_for(
                analyze_email_intent(text, sender=sender_val, subject=subject_val),
                timeout=tier3_timeout,
            )

            execution_ms = (time.perf_counter() - start_time) * 1000.0

            # If result category indicates failure, preserve explicit failure status
            if result.category == "AI_TIMEOUT":
                status = TierStatus.TIMEOUT
            elif result.category in ("AI_UNAVAILABLE", "AI_RATE_LIMITED", "AI_INVALID_RESPONSE", "AI_PROVIDER_ERROR"):
                status = TierStatus.FAILED
            else:
                status = TierStatus.COMPLETE

            return Tier3Result(
                score=int(round(result.threat_score)),
                category=result.category,
                reasoning=result.reasoning,
                flagged_phrases=result.flagged_phrases,
                confidence=float(getattr(result, "confidence", 1.0)),
                requires_visual_check=bool(getattr(result, "requires_visual_check", False)),
                status=status,
                execution_time_ms=execution_ms,
                provider=getattr(result, "provider", None),
                model=getattr(result, "model", None),
            )

        except asyncio.TimeoutError as e:
            logger.warning("Tier 3 execution timed out after %ss", tier3_timeout)
            raise Tier3ExecutionError(f"Timeout: {e}") from e
        except Tier3UnavailableError:
            raise
        except Exception as e:
            logger.error("Tier 3 execution failed: %s", e, exc_info=True)
            raise Tier3ExecutionError(f"Execution error: {e}") from e

    # Define fallback for when circuit is open or execution fails
    async def _tier3_fallback(
        text: str,
        reason: str = "Circuit open or execution failed",
        status: str | TierStatus = "failed",
        category: str = "AI_UNAVAILABLE",
        sender_val: Optional[str] = None,
        subject_val: Optional[str] = None,
    ) -> Tier3Result:
        logger.info("Tier 3 fallback triggered: %s", reason)
        return Tier3Result(
            score=50,
            category=category,
            reasoning=reason,
            flagged_phrases=[],
            confidence=0.0,
            requires_visual_check=False,
            status=_coerce_tier_status(status),
            execution_time_ms=0.0,
            provider="fallback",
            model="none",
        )

    # Execute with circuit breaker if provided
    if circuit_breaker:
        try:
            return await circuit_breaker.call(
                _tier3_execution,
                fallback=_tier3_fallback,
                timeout_seconds=tier3_timeout,
                text=body,
                sender_val=sender,
                subject_val=subject,
            )
        except Tier3UnavailableError as e:
            return await _tier3_fallback(
                body,
                reason=str(e) or "Tier 3 AI provider not configured",
                status="unavailable",
                category="AI_UNAVAILABLE",
            )
        except Tier3ExecutionError as e:
            logger.warning("Tier 3 execution error after circuit breaker: %s", e)
            status_val = "timeout" if "timeout" in str(e).lower() else "failed"
            cat_val = "AI_TIMEOUT" if status_val == "timeout" else "AI_PROVIDER_ERROR"
            return await _tier3_fallback(
                body,
                reason=str(e),
                status=status_val,
                category=cat_val,
            )
        except Exception as e:
            logger.error("Unexpected error in circuit breaker call: %s", e, exc_info=True)
            return await _tier3_fallback(
                body,
                reason=f"Unexpected error: {e}",
                status="failed",
                category="AI_PROVIDER_ERROR",
            )
    else:
        # No circuit breaker – execute directly with error handling
        try:
            return await _tier3_execution(body, sender_val=sender, subject_val=subject)
        except Tier3UnavailableError:
            return await _tier3_fallback(
                body,
                reason="Gemini API key not configured",
                status="unavailable",
                category="AI_UNAVAILABLE",
            )
        except asyncio.TimeoutError:
            return await _tier3_fallback(
                body,
                reason=f"AI analysis timed out after {tier3_timeout}s",
                status="timeout",
                category="AI_TIMEOUT",
            )
        except Tier3ExecutionError as e:
            status_val = "timeout" if "timeout" in str(e).lower() else "failed"
            cat_val = "AI_TIMEOUT" if status_val == "timeout" else "AI_PROVIDER_ERROR"
            return await _tier3_fallback(
                body,
                reason=str(e),
                status=status_val,
                category=cat_val,
            )
        except Exception as e:
            logger.error("Unhandled error in Tier 3: %s", e, exc_info=True)
            return await _tier3_fallback(
                body,
                reason=f"Unexpected error: {e}",
                status="failed",
                category="AI_PROVIDER_ERROR",
            )