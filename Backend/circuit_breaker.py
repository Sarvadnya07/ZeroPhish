"""
Circuit Breaker Pattern Implementation
Prevents cascading failures between Tier 2 and Tier 3 services.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0
    state_transitions: list = field(default_factory=list)
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None

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

    def record_state_transition(self, from_state: CircuitState, to_state: CircuitState) -> None:
        self.state_transitions.append(
            {
                "from": from_state.value,
                "to": to_state.value,
                "timestamp": time.time(),
            }
        )

    def get_failure_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests

    def to_dict(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rejected_requests": self.rejected_requests,
            "failure_rate": self.get_failure_rate(),
            "state_transitions_count": len(self.state_transitions),
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    Transitions:
    - CLOSED -> OPEN: failure threshold reached within the configured window
    - OPEN -> HALF_OPEN: timeout elapsed
    - HALF_OPEN -> CLOSED: one successful probe request
    - HALF_OPEN -> OPEN: probe request fails
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: float = 30.0,
        window: float = 60.0,
        name: str = "circuit_breaker",
    ):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.window = window
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._failure_timestamps: list[float] = []
        self._last_failure_time: Optional[float] = None
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._metrics = CircuitBreakerMetrics()

        logger.info(
            "Circuit breaker '%s' initialized: threshold=%s timeout=%ss window=%ss",
            name,
            failure_threshold,
            timeout,
            window,
        )

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def metrics(self) -> CircuitBreakerMetrics:
        return self._metrics

    async def call(
        self,
        func: Callable[..., Any],
        *args,
        fallback: Optional[Callable[..., Any]] = None,
        **kwargs,
    ) -> Any:
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
                else:
                    self._metrics.record_rejection()
                    logger.warning("Circuit '%s' is OPEN; request rejected", self.name)
                    if fallback:
                        return await fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN")

        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                self._on_success()
            return result
        except Exception:
            async with self._lock:
                self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        if self._opened_at is None:
            return False
        return (time.time() - self._opened_at) >= self.timeout

    def _on_success(self) -> None:
        self._metrics.record_success()

        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            self._failure_timestamps = []
            self._opened_at = None
            logger.info("Circuit '%s' recovered and is now CLOSED", self.name)

    def _on_failure(self) -> None:
        now = time.time()
        self._metrics.record_failure()
        self._last_failure_time = now

        if self._state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
            self._opened_at = now
            self._failure_timestamps = [now]
            self._failure_count = 1
            logger.warning("Circuit '%s' failed probe and returned to OPEN", self.name)
            return

        if self._state == CircuitState.CLOSED:
            self._failure_timestamps.append(now)
            cutoff = now - self.window
            self._failure_timestamps = [ts for ts in self._failure_timestamps if ts >= cutoff]
            self._failure_count = len(self._failure_timestamps)

            if self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN)
                self._opened_at = now
                logger.error("Circuit '%s' OPENED after %s failures", self.name, self._failure_count)

    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self._metrics.record_state_transition(old_state, new_state)
        logger.info("Circuit '%s': %s -> %s", self.name, old_state.value, new_state.value)

    def reset(self) -> None:
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._failure_timestamps = []
        self._last_failure_time = None
        self._opened_at = None
        logger.info("Circuit '%s' manually reset to CLOSED", self.name)

    def get_status(self) -> dict:
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


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and no fallback is provided."""

    pass
