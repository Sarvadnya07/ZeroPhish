"""
Incident service — Repository-backed ticket store for Security Operations Centers.
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional

from repositories.factory import get_incident_repository

from .models import (
    Incident,
    IncidentComment,
    IncidentCommentCreate,
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)

# Backwards-compatible module-level store reference for test fixtures
_store: Dict[str, Incident] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _auto_severity(score: Optional[float]) -> IncidentSeverity:
    if score is None:
        return IncidentSeverity.MEDIUM
    if score >= 80:
        return IncidentSeverity.CRITICAL
    if score >= 70:
        return IncidentSeverity.HIGH
    if score >= 50:
        return IncidentSeverity.MEDIUM
    if score >= 30:
        return IncidentSeverity.LOW
    return IncidentSeverity.INFO


class IncidentService:

    @staticmethod
    def create(data: IncidentCreate, reporter_id: Optional[str] = None) -> Incident:
        repo = get_incident_repository()
        iid = str(uuid.uuid4())
        now = _now()
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
        saved = repo.save(incident)
        _store[saved.id] = saved
        return saved

    @staticmethod
    def get(incident_id: str) -> Optional[Incident]:
        repo = get_incident_repository()
        inc = repo.get_by_id(incident_id)
        if not inc:
            return _store.get(incident_id)
        return inc

    @staticmethod
    def list_all(
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Incident]:
        repo = get_incident_repository()
        return repo.list_all(
            status=status, severity=severity, assignee_id=assignee_id, reporter_id=reporter_id
        )

    @staticmethod
    def update(incident_id: str, update: IncidentUpdate) -> Optional[Incident]:
        repo = get_incident_repository()
        inc = repo.update(incident_id, update)
        if inc:
            _store[incident_id] = inc
        return inc

    @staticmethod
    def add_comment(
        incident_id: str,
        data: IncidentCommentCreate,
        author_id: str,
        author_name: str,
    ) -> Optional[Incident]:
        repo = get_incident_repository()
        comment = IncidentComment(
            id=str(uuid.uuid4()),
            author_id=author_id,
            author_name=author_name,
            body=data.body,
            created_at=_now(),
        )
        inc = repo.add_comment(incident_id, comment)
        if inc:
            _store[incident_id] = inc
        return inc

    @staticmethod
    def delete(incident_id: str) -> bool:
        repo = get_incident_repository()
        _store.pop(incident_id, None)
        return repo.delete(incident_id)

    @staticmethod
    def stats() -> dict:
        repo = get_incident_repository()
        return repo.stats()
