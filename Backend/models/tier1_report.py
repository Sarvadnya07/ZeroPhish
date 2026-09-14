"""
Permissive payload model for the /tier1/report endpoint.

The Chrome extension and internal pipelines POST free-form scan reports here.
The payload is intentionally permissive — every field optional, extra fields
allowed — because this endpoint's contract is "store and broadcast the latest
report for the live dashboard", not strict validation. A malformed report must
never 400-reject the dashboard update path.

Downstream consumers (SSE subscribers, /tier1/latest) read the payload as a
dict; this model exists to give the boundary a named, documented shape and a
single place to tighten later if the extension contract stabilizes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Tier1ReportPayload(BaseModel):
    """Known fields of a Tier 1 report; unknown fields are preserved."""

    model_config = ConfigDict(extra="allow")

    scan_id: Optional[str] = None
    event_id: Optional[str] = None
    timestamp: Optional[Any] = None
    source: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    final_score: Optional[float] = None
    partial_score: Optional[float] = None
    verdict: Optional[str] = None
    layers_completed: Optional[int] = Field(default=None, ge=0, le=3)
    evidence: Optional[List[str]] = None

    def model_dump(self, **kwargs: Any) -> Dict[str, Any]:
        # Preserve unknown fields in the serialized payload so broadcast
        # consumers keep receiving exactly what the extension sent.
        return super().model_dump(**kwargs)
