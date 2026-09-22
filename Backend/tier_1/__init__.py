"""
ZeroPhish Tier 1 Server-Side Detection Package.

Provides authoritative, fast heuristic analysis for email content, senders, and links.
"""

from .engine import (
    ServerTier1Result,
    analyze_tier1_server,
    classify_tier1_category,
    sanitize_client_evidence,
)

__all__ = [
    "ServerTier1Result",
    "analyze_tier1_server",
    "classify_tier1_category",
    "sanitize_client_evidence",
]
