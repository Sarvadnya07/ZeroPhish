"""
Circuit Breaker Pattern Implementation

Prevents cascading failures between Tier 2 and Tier 3 services.
Implements the classic circuit breaker pattern with three states:
- CLOSED: normal operation, failures are counted.
- OPEN: failures exceed threshold; requests are rejected (or fallback used).
- HALF_OPEN: probe state to test if the service has recovered.

Supports async/await, configurable thresholds, timeouts, and metrics.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Awaitable, ParamSpec

logger = logging.getLogger(__name__)

# ---------- Configuration from Environment ----------
DEFAULT_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
DEFAULT_TIMEOUT = float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "30.0"))
DEFAULT_WINDOW = float(os.getenv("CIRCUIT_BREAKER_WINDOW", "60.0"))
DEFAULT_NAME = os.getenv("CIRCUIT_BREAKER_NAME", "default")

# ---------- Enums ----------
class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

# ---------- Exceptions ----------
class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and no fallback is provided."""
    pass

class CircuitBreakerTimeoutError(Exception):
    """Raised when a call exceeds the operation timeout (optional)."""
    pass

# ---------- Metrics ----------
@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    half_open_probes: int = 0
    half_open_successes: int = 0
    half_open_failures: int = 0
    state_transitions: List[Dict[str, Any]] = field(default_factory=list)
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    last_state_change_time: Optional[float] = None

    def record_success(self) -> None:
        self.total_requests += 1
        self.successful_requests += 1
        self.last_success_time = time.time()

    def record_failure(self) -> None:
        self.total_requests += 1
        self.failed_requests += 1
        self.last_failure_time = time.time()

    def record_rejection(self) -> None:
        self.rejected_requests += 1

    def record_half_open_probe(self) -> None:
        self.half_open_probes += 1

    def record_half_open_success(self) -> None:
        self.half_open_successes += 1

    def record_half_open_failure(self) -> None:
        self.half_open_failures += 1

    def record_state_transition(self, from_state: CircuitState, to_state: CircuitState) -> None:
        self.state_transitions.append({
            "from": from_state.value,
            "to": to_state.value,
            "timestamp": time.time(),
        })
        self.last_state_change_time = time.time()

    def get_failure_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rejected_requests": self.rejected_requests,
            "half_open_probes": self.half_open_probes,
            "half_open_successes": self.half_open_successes,
            "half_open_failures": self.half_open_failures,
            "failure_rate": self.get_failure_rate(),
            "state_transitions_count": len(self.state_transitions),
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
            "last_state_change_time": self.last_state_change_time,
        }

# ---------- Circuit Breaker Class ----------
T = TypeVar("T")
P = ParamSpec("P")

class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    States:
        CLOSED: normal operation, failures are counted within a sliding window.
        OPEN: failures exceed threshold; requests are rejected (or fallback used).
        HALF_OPEN: after timeout, one request is allowed to probe recovery.

    Attributes:
        failure_threshold: Number of failures within the window to open the circuit.
        timeout: Time (seconds) to wait before transitioning from OPEN to HALF_OPEN.
        window: Time window (seconds) for counting failures.
        name: Identifier for logging and monitoring.
    """

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        timeout: float = DEFAULT_TIMEOUT,
        window: float = DEFAULT_WINDOW,
        name: str = DEFAULT_NAME,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.window = window
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._failure_timestamps: List[float] = []
        self._last_failure_time: Optional[float] = None
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._metrics = CircuitBreakerMetrics()

        logger.info(
            "CircuitBreaker '%s' initialized: threshold=%d, timeout=%.2fs, window=%.2fs",
            name, failure_threshold, timeout, window,
        )

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def metrics(self) -> CircuitBreakerMetrics:
        return self._metrics

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        return self._state == CircuitState.HALF_OPEN

    async def call(
        self,
        func: Callable[P, Awaitable[T]],
        fallback: Optional[Callable[P, Awaitable[T]]] = None,
        timeout_seconds: Optional[float] = None,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T:
        """
        Execute the given async function with circuit breaker protection.

        Args:
            func: Async function to call.
            *args: Positional arguments for the function.
            fallback: Optional async function to call if circuit is open or call fails.
            timeout_seconds: Optional per‑call timeout.
            **kwargs: Keyword arguments for the function.

        Returns:
            The result of `func` or `fallback`.

        Raises:
            CircuitBreakerOpenError: If circuit is open and no fallback provided.
            CircuitBreakerTimeoutError: If the call exceeds `timeout_seconds`.
            Exception: Any exception from `func` (unless handled by fallback).
        """
        # 1. Check state under lock
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
                else:
                    self._metrics.record_rejection()
                    logger.warning("Circuit '%s' OPEN; request rejected", self.name)
                    if fallback:
                        return await fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN")

        # 2. Execute the call (with optional timeout)
        try:
            if timeout_seconds is not None:
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            else:
                result = await func(*args, **kwargs)

            # 3. Record success
            async with self._lock:
                self._on_success()
            return result

        except (asyncio.TimeoutError, TimeoutError) as e:
            logger.warning("Circuit '%s' call timed out: %s", self.name, e)
            async with self._lock:
                self._on_failure(error=e)
            if fallback:
                return await fallback(*args, **kwargs)
            raise CircuitBreakerTimeoutError(f"Call to circuit '{self.name}' timed out") from e

        except Exception as e:
            logger.warning("Circuit '%s' call failed: %s", self.name, e)
            async with self._lock:
                self._on_failure(error=e)
            if fallback:
                return await fallback(*args, **kwargs)
            raise

    def _should_attempt_reset(self) -> bool:
        if self._opened_at is None:
            return False
        return (time.time() - self._opened_at) >= self.timeout

    def _on_success(self) -> None:
        self._metrics.record_success()

        if self._state == CircuitState.HALF_OPEN:
            self._metrics.record_half_open_success()
            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            self._failure_timestamps = []
            self._opened_at = None
            logger.info("Circuit '%s' probe succeeded; restored to CLOSED", self.name)

        elif self._state == CircuitState.CLOSED:
            # No state change needed; just update metrics
            pass

    def _on_failure(self, error: Optional[Exception] = None) -> None:
        now = time.time()
        self._metrics.record_failure()
        self._last_failure_time = now

        # If in half-open, failure immediately re-opens the circuit
        if self._state == CircuitState.HALF_OPEN:
            self._metrics.record_half_open_failure()
            self._transition_to(CircuitState.OPEN)
            self._opened_at = now
            self._failure_timestamps = [now]
            self._failure_count = 1
            logger.warning("Circuit '%s' probe failed; returned to OPEN", self.name)
            return

        # If closed, accumulate failures in sliding window
        if self._state == CircuitState.CLOSED:
            self._failure_timestamps.append(now)
            cutoff = now - self.window
            self._failure_timestamps = [ts for ts in self._failure_timestamps if ts >= cutoff]
            self._failure_count = len(self._failure_timestamps)

            if self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN)
                self._opened_at = now
                logger.error(
                    "Circuit '%s' OPENED after %d failures in %.2fs window",
                    self.name, self._failure_count, self.window,
                )

    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self._metrics.record_state_transition(old_state, new_state)
        logger.info("Circuit '%s': %s -> %s", self.name, old_state.value, new_state.value)

    def reset(self) -> None:
        """Manually reset the circuit to CLOSED state."""
        async def _reset():
            async with self._lock:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._failure_timestamps = []
                self._last_failure_time = None
                self._opened_at = None
                logger.info("Circuit '%s' manually reset to CLOSED", self.name)
        asyncio.create_task(_reset())

    async def async_reset(self) -> None:
        """Async version of reset (for use in routes)."""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._failure_timestamps = []
            self._last_failure_time = None
            self._opened_at = None
            logger.info("Circuit '%s' manually reset to CLOSED (async)", self.name)

    def get_status(self) -> Dict[str, Any]:
        """Return current status and metrics."""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "timeout": self.timeout,
            "window": self.window,
            "opened_at": self._opened_at,
            "last_failure_time": self._last_failure_time,
            "metrics": self._metrics.to_dict(),
        }


# ---------- Decorator ----------
def circuit_breaker(
    breaker: Optional[CircuitBreaker] = None,
    fallback: Optional[Callable[P, Awaitable[T]]] = None,
    timeout_seconds: Optional[float] = None,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """
    Decorator for wrapping async functions with circuit breaker protection.

    Usage:
        cb = CircuitBreaker(name="my_service")
        @circuit_breaker(breaker=cb, fallback=my_fallback)
        async def my_call(x: int) -> str:
            return await some_service(x)
    """
    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            nonlocal breaker
            if breaker is None:
                # Use a default circuit breaker if none provided
                breaker = CircuitBreaker()
            return await breaker.call(
                func,
                *args,
                fallback=fallback,
                timeout_seconds=timeout_seconds,
                **kwargs,
            )
        return wrapper
    return decorator