"""
Incident data models — ticket lifecycle, severity, analyst workflow.

Defines the data contracts for Security Operations Center (SOC) incidents,
including severity levels, statuses, comments, and lifecycle transitions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------- Enums ----------
class IncidentSeverity(str, Enum):
    """Severity level of an incident."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    """Lifecycle status of an incident."""
    OPEN = "open"
    TRIAGING = "triaging"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POS = "false_positive"


# ---------- Models ----------
class IncidentComment(BaseModel):
    """A comment on an incident, with author metadata."""
    id: str = Field(..., min_length=1, description="Unique comment ID")
    author_id: str = Field(..., min_length=1, description="User ID of the author")
    author_name: str = Field(..., min_length=1, max_length=100, description="Display name of the author")
    body: str = Field(..., min_length=1, max_length=2048, description="Comment text")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Comment body cannot be empty")
        return v.strip()


class Incident(BaseModel):
    """A complete incident record with lifecycle tracking."""
    id: str = Field(..., min_length=1, description="Unique incident ID")
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(..., max_length=4096)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    scan_id: Optional[str] = Field(None, description="Linked gateway scan ID")
    reporter_id: Optional[str] = Field(None, description="User who flagged the incident")
    assignee_id: Optional[str] = Field(None, description="User assigned to resolve")
    final_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    sender: Optional[str] = Field(None, max_length=320)
    subject: Optional[str] = Field(None, max_length=1000)
    evidence: List[str] = Field(default_factory=list, description="URLs, hashes, etc.")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    comments: List[IncidentComment] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    false_positive: bool = False

    def mark_resolved(self) -> None:
        """Update status to RESOLVED and set resolved_at timestamp."""
        self.status = IncidentStatus.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)


class IncidentCreate(BaseModel):
    """Payload for creating a new incident."""
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(..., min_length=1, max_length=4096)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    scan_id: Optional[str] = None
    sender: Optional[str] = Field(None, max_length=320)
    subject: Optional[str] = Field(None, max_length=1000)
    final_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    evidence: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    @field_validator("title", "description")
    @classmethod
    def validate_not_empty(cls, v: str, info) -> str:
        if not v or not v.strip():
            raise ValueError(f"{info.field_name} cannot be empty")
        return v.strip()


class IncidentUpdate(BaseModel):
    """Payload for updating an incident (analysts only)."""
    title: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = Field(None, max_length=4096)
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assignee_id: Optional[str] = None
    tags: Optional[List[str]] = None
    false_positive: Optional[bool] = None

    @field_validator("title", "description")
    @classmethod
    def validate_not_empty(cls, v: Optional[str], info) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError(f"{info.field_name} cannot be empty if provided")
        return v.strip() if v else v


class IncidentCommentCreate(BaseModel):
    """Payload for adding a comment to an incident."""
    body: str = Field(..., min_length=1, max_length=2048)

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Comment body cannot be empty")
        return v.strip()