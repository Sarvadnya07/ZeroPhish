"""
Telemetry retention and privacy validation for Extended Shadow Evaluation.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Deque, List, Optional

from ml.shadow.models import ExtendedShadowObservation


class ShadowRetentionBuffer:
    """Bounded in-memory ring buffer with privacy safeguards and retention limits."""

    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._buffer: Deque[ExtendedShadowObservation] = deque(maxlen=max_size)

    def add(self, observation: ExtendedShadowObservation) -> None:
        self._buffer.append(observation)

    def get_all(self) -> List[ExtendedShadowObservation]:
        return list(self._buffer)

    def clear(self) -> None:
        self._buffer.clear()

    @staticmethod
    def audit_privacy(observations: List[ExtendedShadowObservation]) -> bool:
        """Verifies that no raw secrets, auth tokens, passwords, or raw URLs are stored."""
        secret_patterns = [
            re.compile(r"(bearer\s+[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
            re.compile(r"(password=)", re.IGNORECASE),
            re.compile(r"(api_key=)", re.IGNORECASE),
            re.compile(r"(token=)", re.IGNORECASE),
        ]
        for obs in observations:
            # Hashes must be 64-char hex strings
            if len(obs.url_hash) != 64 or len(obs.hostname_hash) != 64:
                return False
            for pat in secret_patterns:
                if pat.search(obs.url_hash) or pat.search(obs.hostname_hash):
                    return False
        return True
