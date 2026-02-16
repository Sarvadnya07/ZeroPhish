"""
Circuit Breaker Pattern Implementation
Prevents cascading failures between Tier 2 and Tier 3 services
"""

import asyncio
import logging
import time
from enum import Enum
from typing import Callable, Optional, TypeVar, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0  # Rejected due to open circuit
    state_transitions: list = field(default_factory=list)
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None

    def record_success(self):
        """Record a successful request."""
        self.total_requests += 1
        self.successful_requests += 1
        self.last_success_time = time.time()

    def record_failure(self):
        """Record a failed request."""
        self.total_requests += 1
        self.failed_requests += 1
        self.last_failure_time = time.time()

    def record_rejection(self):
        """Record a rejected request (circuit open)."""
        self.rejected_requests += 1

    def record_state_transition(self, from_state: CircuitState, to_state: CircuitState):
        """Record a state transition."""
        self.state_transitions.append(
            {
                "from": from_state.value,
                "to": to_state.value,
                "timestamp": time.time(),
            }
        )

    def get_failure_rate(self) -> float:
        """Calculate failure rate (0.0 to 1.0)."""
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests

    def to_dict(self) -> dict:
        """Convert metrics to dictionary."""
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

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, reject requests immediately
    - HALF_OPEN: Testing recovery, allow limited requests

    Transitions:
    - CLOSED → OPEN: When failure count exceeds threshold in time window
    - OPEN → HALF_OPEN: After timeout period
    - HALF_OPEN → CLOSED: On successful request
    - HALF_OPEN → OPEN: On failed request
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: float = 30.0,  # seconds
        window: float = 60.0,  # seconds
        name: str = "circuit_breaker",
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures to trigger OPEN state
            timeout: Seconds to wait before transitioning to HALF_OPEN
            window: Time window for counting failures (seconds)
            name: Name for logging and identification
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.window = window
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._metrics = CircuitBreakerMetrics()

        logger.info(
            f"🔌 Circuit breaker '{name}' initialized: "
            f"threshold={failure_threshold}, timeout={timeout}s, window={window}s"
        )

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def metrics(self) -> CircuitBreakerMetrics:
        """Get circuit breaker metrics."""
        return self._metrics

    async def call(
        self, func: Callable[..., Any], *args, fallback: Optional[Callable] = None, **kwargs
    ) -> Any:
        """
        Execute function with circuit breaker protection.

        Args:
            func: Async function to execute
            *args: Positional arguments for func
            fallback: Optional fallback function if circuit is open
            **kwargs: Keyword arguments for func

        Returns:
            Result from func or fallback

        Raises:
            CircuitBreakerOpenError: If circuit is open and no fallback provided
        """
        async with self._lock:
            # Check if we should transition from OPEN to HALF_OPEN
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
                else:
                    # Circuit still open, reject request
                    self._metrics.record_rejection()
                    logger.warning(
                        f"⚠️ Circuit '{self.name}' is OPEN, request rejected"
                    )

                    if fallback:
                        logger.info(f"🔄 Using fallback for '{self.name}'")
                        return await fallback(*args, **kwargs)
                    else:
                        raise CircuitBreakerOpenError(
                            f"Circuit breaker '{self.name}' is OPEN"
                        )

        # Execute the function
        try:
            result = await func(*args, **kwargs)

            # Success - update state
            async with self._lock:
                self._on_success()

            return result

        except Exception as e:
            # Failure - update state
            async with self._lock:
                self._on_failure()

            # Re-raise the exception
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._opened_at is None:
            return False

        elapsed = time.time() - self._opened_at
        return elapsed >= self.timeout

    def _on_success(self):
        """Handle successful request."""
        self._metrics.record_success()

        if self._state == CircuitState.HALF_OPEN:
            # Success in HALF_OPEN → transition to CLOSED
            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            logger.info(f"✅ Circuit '{self.name}' recovered, now CLOSED")

    def _on_failure(self):
        """Handle failed request."""
        self._metrics.record_failure()
        self._last_failure_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            # Failure in HALF_OPEN → back to OPEN
            self._transition_to(CircuitState.OPEN)
            self._opened_at = time.time()
            logger.warning(
                f"❌ Circuit '{self.name}' failed recovery attempt, back to OPEN"
            )
            return

        if self._state == CircuitState.CLOSED:
            # Increment failure count
            self._failure_count += 1

            # Clean up old failures outside the window
            if self._last_failure_time:
                time_since_last = time.time() - self._last_failure_time
                if time_since_last > self.window:
                    # Reset counter if outside window
                    self._failure_count = 1

            # Check if we should open the circuit
            if self._failure_count >= self.failure_threshold:
                self._transition_to(CircuitState.OPEN)
                self._opened_at = time.time()
                logger.error(
                    f"🔴 Circuit '{self.name}' OPENED after {self._failure_count} failures"
                )

    def _transition_to(self, new_state: CircuitState):
        """Transition to a new state."""
        old_state = self._state
        self._state = new_state
        self._metrics.record_state_transition(old_state, new_state)
        logger.info(f"🔄 Circuit '{self.name}': {old_state.value} → {new_state.value}")

    def reset(self):
        """Manually reset the circuit breaker to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None
            self._opened_at = None
            logger.info(f"🔄 Circuit '{self.name}' manually reset to CLOSED")

    def get_status(self) -> dict:
        """Get current circuit breaker status."""
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
