"""Incident service — in-memory ticket store."""
from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional

from .models import (
    Incident,
    IncidentComment,
    IncidentCommentCreate,
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)

_store: Dict[str, Incident] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _auto_severity(score: Optional[float]) -> IncidentSeverity:
    if score is None:
        return IncidentSeverity.MEDIUM
    if score >= 80: return IncidentSeverity.CRITICAL
    if score >= 70: return IncidentSeverity.HIGH
    if score >= 50: return IncidentSeverity.MEDIUM
    if score >= 30: return IncidentSeverity.LOW
    return IncidentSeverity.INFO


class IncidentService:

    @staticmethod
    def create(data: IncidentCreate, reporter_id: Optional[str] = None) -> Incident:
        iid = str(uuid.uuid4())
        now = _now()
        # Auto-elevate severity based on scan score if not specified
        severity = data.severity
        if data.final_score is not None and data.severity == IncidentSeverity.MEDIUM:
            severity = _auto_severity(data.final_score)
        incident = Incident(
            id=iid,
            title=data.title,
            description=data.description,
            severity=severity,
            scan_id=data.scan_id,
            reporter_id=reporter_id,
            final_score=data.final_score,
            sender=data.sender,
            subject=data.subject,
            evidence=data.evidence,
            tags=data.tags,
            created_at=now,
            updated_at=now,
        )
        _store[iid] = incident
        return incident

    @staticmethod
    def get(incident_id: str) -> Optional[Incident]:
        return _store.get(incident_id)

    @staticmethod
    def list_all(
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Incident]:
        items = list(_store.values())
        if status:
            items = [i for i in items if i.status == status]
        if severity:
            items = [i for i in items if i.severity == severity]
        if assignee_id:
            items = [i for i in items if i.assignee_id == assignee_id]
        if reporter_id:
            items = [i for i in items if i.reporter_id == reporter_id]
        return sorted(items, key=lambda i: i.created_at, reverse=True)

    @staticmethod
    def update(incident_id: str, update: IncidentUpdate) -> Optional[Incident]:
        inc = _store.get(incident_id)
        if not inc:
            return None
        if update.title is not None:       inc.title       = update.title
        if update.description is not None: inc.description = update.description
        if update.severity is not None:    inc.severity    = update.severity
        if update.assignee_id is not None: inc.assignee_id = update.assignee_id
        if update.tags is not None:        inc.tags        = update.tags
        if update.false_positive is not None:
            inc.false_positive = update.false_positive
        if update.status is not None:
            inc.status = update.status
            if update.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POS):
                inc.resolved_at = _now()
        inc.updated_at = _now()
        return inc

    @staticmethod
    def add_comment(
        incident_id: str,
        data: IncidentCommentCreate,
        author_id: str,
        author_name: str,
    ) -> Optional[Incident]:
        inc = _store.get(incident_id)
        if not inc:
            return None
        comment = IncidentComment(
            id=str(uuid.uuid4()),
            author_id=author_id,
            author_name=author_name,
            body=data.body,
            created_at=_now(),
        )
        inc.comments.append(comment)
        inc.updated_at = _now()
        return inc

    @staticmethod
    def delete(incident_id: str) -> bool:
        return _store.pop(incident_id, None) is not None

    @staticmethod
    def stats() -> dict:
        items = list(_store.values())
        return {
            "total": len(items),
            "open":        sum(1 for i in items if i.status == IncidentStatus.OPEN),
            "triaging":    sum(1 for i in items if i.status == IncidentStatus.TRIAGING),
            "in_progress": sum(1 for i in items if i.status == IncidentStatus.IN_PROGRESS),
            "resolved":    sum(1 for i in items if i.status == IncidentStatus.RESOLVED),
            "false_positives": sum(1 for i in items if i.false_positive),
            "by_severity": {
                s.value: sum(1 for i in items if i.severity == s)
                for s in IncidentSeverity
            },
        }
