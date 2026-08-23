"""
Base Threat Feed Adapter Protocol and Interface.
Defines contracts for secure, rate-limited, legally governed threat-feed ingestion.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable

from ..schemas.v3 import FeedIngestionStatus, SourceGovernance


@runtime_checkable
class ThreatFeedAdapter(Protocol):
    """Protocol for all threat-intelligence and benign dataset ingestion adapters."""

    def fetch_records(self) -> List[Dict[str, Any]]:
        """Fetch raw records without executing URLs or browsing arbitrary targets."""
        ...

    def get_governance(self) -> SourceGovernance:
        """Return legal, licensing, and access policy metadata."""
        ...

    def get_feed_status(self) -> FeedIngestionStatus:
        """Return current operational status of the feed."""
        ...
