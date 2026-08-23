"""
Incident data models — ticket lifecycle, severity, analyst workflow.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POS = "false_positive"


class IncidentComment(BaseModel):
    id: str
    author_id: str
    author_name: str
    body: str
    created_at: str


class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    scan_id: Optional[str] = None  # linked gateway scan
    reporter_id: Optional[str] = None  # user who flagged it
    assignee_id: Optional[str] = None
    final_score: Optional[float] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    comments: List[IncidentComment] = Field(default_factory=list)
    created_at: str
    updated_at: str
    resolved_at: Optional[str] = None
    false_positive: bool = False


class IncidentCreate(BaseModel):
    title: str = Field(..., max_length=256)
    description: str = Field(..., max_length=4096)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    scan_id: Optional[str] = None
    sender: Optional[str] = Field(None, max_length=320)
    subject: Optional[str] = Field(None, max_length=1000)
    final_score: Optional[float] = None
    evidence: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = Field(None, max_length=4096)
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assignee_id: Optional[str] = None
    tags: Optional[List[str]] = None
    false_positive: Optional[bool] = None


class IncidentCommentCreate(BaseModel):
    body: str = Field(..., max_length=2048)
