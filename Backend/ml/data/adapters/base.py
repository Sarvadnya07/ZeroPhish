"""
Base Threat Feed Adapter Protocol and Interface.

Defines contracts for secure, rate-limited, legally governed threat-feed ingestion.
All adapters must implement the ThreatFeedAdapter protocol.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable

from ..schemas.v3 import FeedIngestionStatus, SourceGovernance


@runtime_checkable
class ThreatFeedAdapter(Protocol):
    """
    Protocol for all threat-intelligence and benign dataset ingestion adapters.

    Implementations must provide:
    - fetch_records(): A method to retrieve raw records from the feed.
    - get_governance(): Legal and licensing metadata.
    - get_feed_status(): Current operational status.
    """

    def fetch_records(self) -> List[Dict[str, Any]]:
        """
        Fetch raw records from the data source.

        Returns:
            A list of dictionaries, each containing at minimum:
            - 'url': The URL or domain string.
            - 'label': 0 for benign, 1 for malicious.
            - 'source': A source identifier string.
            - 'source_record_id': Unique ID from the source.
            - 'observed_at': ISO date string.

        Raises:
            ValueError: On validation errors.
            Exception: On network or parsing errors.
        """
        ...

    def get_governance(self) -> SourceGovernance:
        """
        Return legal, licensing, and access policy metadata.

        Returns:
            SourceGovernance dataclass with all required fields.
        """
        ...

    def get_feed_status(self) -> FeedIngestionStatus:
        """
        Return the current operational status of the feed.

        Returns:
            FeedIngestionStatus enum value.
        """
        ...