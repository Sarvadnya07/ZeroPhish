"""
Telemetry retention and privacy validation for Extended Shadow Evaluation.

Provides a bounded in-memory ring buffer with privacy safeguards and retention limits.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Deque, List, Optional

from ml.shadow.models import ExtendedShadowObservation


class ShadowRetentionBuffer:
    """
    Bounded in-memory ring buffer with privacy safeguards and retention limits.

    Attributes:
        max_size: Maximum number of observations to retain.
        _buffer: Deque with maxlen enforcing automatic eviction.
    """

    # Default sensitive patterns for privacy audit
    DEFAULT_SENSITIVE_PATTERNS = [
        re.compile(r"(bearer\s+[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
        re.compile(r"(password=)", re.IGNORECASE),
        re.compile(r"(api_key=)", re.IGNORECASE),
        re.compile(r"(token=)", re.IGNORECASE),
        re.compile(r"(auth=)", re.IGNORECASE),
        re.compile(r"(secret=)", re.IGNORECASE),
        re.compile(r"(session=)", re.IGNORECASE),
    ]

    def __init__(self, max_size: int = 5000, sensitive_patterns: Optional[List[re.Pattern]] = None):
        """
        Initialize the retention buffer.

        Args:
            max_size: Maximum number of observations to store (must be > 0).
            sensitive_patterns: List of compiled regex patterns for privacy audit.
                Defaults to DEFAULT_SENSITIVE_PATTERNS.
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.max_size = max_size
        self._buffer: Deque[ExtendedShadowObservation] = deque(maxlen=max_size)
        self.sensitive_patterns = sensitive_patterns or self.DEFAULT_SENSITIVE_PATTERNS

    def add(self, observation: ExtendedShadowObservation) -> None:
        """
        Add an observation to the buffer (FIFO with automatic eviction).

        Args:
            observation: The observation to store.
        """
        if not observation:
            raise ValueError("Observation cannot be None")
        self._buffer.append(observation)

    def get_all(self) -> List[ExtendedShadowObservation]:
        """Return all stored observations as a list (oldest first)."""
        return list(self._buffer)

    def clear(self) -> None:
        """Clear all observations from the buffer."""
        self._buffer.clear()

    def size(self) -> int:
        """Return the current number of stored observations."""
        return len(self._buffer)

    def is_full(self) -> bool:
        """Return True if the buffer has reached its capacity."""
        return len(self._buffer) >= self.max_size

    def audit_privacy(self_or_cls, observations: Optional[List[ExtendedShadowObservation]] = None) -> bool:
        """
        Verify that no raw secrets, auth tokens, passwords, or raw URLs are stored.

        Checks:
        - url_hash and hostname_hash are 64-character hex strings.
        - No sensitive patterns match in the hashes (should never, but as a safeguard).

        Args:
            observations: List of observations to audit; uses all stored if None.

        Returns:
            True if all privacy requirements are satisfied, False otherwise.
        """
        if isinstance(self_or_cls, list):
            obs_list = self_or_cls
            patterns = ShadowRetentionBuffer.DEFAULT_SENSITIVE_PATTERNS
        elif isinstance(self_or_cls, ShadowRetentionBuffer):
            obs_list = observations if observations is not None else self_or_cls.get_all()
            patterns = self_or_cls.sensitive_patterns
        else:
            obs_list = observations or []
            patterns = getattr(self_or_cls, "DEFAULT_SENSITIVE_PATTERNS", ShadowRetentionBuffer.DEFAULT_SENSITIVE_PATTERNS)

        for obs in obs_list:
            # Hashes must be exactly 64 hex characters
            if len(obs.url_hash) != 64 or len(obs.hostname_hash) != 64:
                return False
            # Validate hex
            try:
                int(obs.url_hash, 16)
                int(obs.hostname_hash, 16)
            except ValueError:
                return False

            # Additionally, ensure no sensitive patterns (should be redundant)
            for pattern in patterns:
                if pattern.search(obs.url_hash) or pattern.search(obs.hostname_hash):
                    return False

            # Ensure no raw secrets in the observation fields themselves
            # (This is a simplified check; in practice, we'd audit all string fields)
            # Use getattr for optional fields (e.g. error may not exist on the model)
            fields_to_check = [
                getattr(obs, "production_verdict", None),
                getattr(obs, "cascade_verdict", None),
                getattr(obs, "security_override", None),
                getattr(obs, "error", None),
            ]
            for field in fields_to_check:
                if field:
                    for pattern in patterns:
                        if pattern.search(field):
                            return False

        return True

    def get_latest(self, n: int = 10) -> List[ExtendedShadowObservation]:
        """Return the most recent n observations."""
        if n <= 0:
            return []
        return list(self._buffer)[-n:]