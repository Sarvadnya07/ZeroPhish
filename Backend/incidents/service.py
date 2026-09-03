"""
Incident service — Repository-backed ticket store for Security Operations Centers.

Manages the full lifecycle of security incidents: creation, updates, commenting,
and deletion. Integrates with the repository layer for persistence.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
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

logger = logging.getLogger(__name__)

# In-memory fallback for development and testing
_IN_MEMORY_STORE: Dict[str, Incident] = {}
_store = _IN_MEMORY_STORE

def _maybe_await(res):
    import inspect
    import asyncio
    if inspect.isawaitable(res):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(res)).result()
        else:
            return asyncio.run(res)
    return res


# ---------- Constants ----------
SEVERITY_SCORE_THRESHOLDS = [
    (80, IncidentSeverity.CRITICAL),
    (70, IncidentSeverity.HIGH),
    (50, IncidentSeverity.MEDIUM),
    (30, IncidentSeverity.LOW),
]


def _auto_severity(score: Optional[float]) -> IncidentSeverity:
    """Map a score (0-100) to a severity level."""
    if score is None:
        return IncidentSeverity.MEDIUM
    for threshold, severity in SEVERITY_SCORE_THRESHOLDS:
        if score >= threshold:
            return severity
    return IncidentSeverity.INFO


def _now() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


class IncidentService:
    """Service for incident lifecycle operations."""

    @staticmethod
    def _get_repository():
        """Retrieve repository, falling back to in-memory store if unavailable."""
        try:
            return get_incident_repository()
        except Exception as e:
            logger.warning("Incident repository unavailable, using in-memory fallback: %s", e)
            return None

    @staticmethod
    def create(data: IncidentCreate, reporter_id: Optional[str] = None) -> Incident:
        """
        Create a new incident from the provided data.

        If the final score is provided and no severity is explicitly set,
        the severity is auto-derived from the score.
        """
        repo = IncidentService._get_repository()
        incident_id = str(uuid.uuid4())
        now = _now()

        # Determine severity: auto-derive from score if available and severity is default
        severity = data.severity
        if data.final_score is not None and severity == IncidentSeverity.MEDIUM:
            severity = _auto_severity(data.final_score)

        incident = Incident(
            id=incident_id,
            title=data.title.strip(),
            description=data.description.strip(),
            severity=severity,
            status=IncidentStatus.OPEN,
            scan_id=data.scan_id,
            reporter_id=reporter_id,
            assignee_id=None,
            final_score=data.final_score,
            sender=data.sender,
            subject=data.subject,
            evidence=data.evidence or [],
            tags=data.tags or [],
            created_at=now,
            updated_at=now,
            resolved_at=None,
            false_positive=False,
        )

        _IN_MEMORY_STORE[incident_id] = incident
        if repo:
            saved = _maybe_await(repo.save(incident))
        else:
            saved = incident

        logger.info("Incident %s created by %s, severity=%s", incident_id, reporter_id or "system", severity.value)
        return saved

    @staticmethod
    def get(incident_id: str) -> Optional[Incident]:
        """Retrieve a single incident by ID."""
        if not incident_id:
            return None

        inc = _IN_MEMORY_STORE.get(incident_id)
        if not inc:
            repo = IncidentService._get_repository()
            if repo:
                inc = _maybe_await(repo.get_by_id(incident_id))
                if inc:
                    _IN_MEMORY_STORE[incident_id] = inc
        return inc

    @staticmethod
    def list_all(
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Incident]:
        """List incidents with optional filters."""
        repo = IncidentService._get_repository()
        if repo:
            return _maybe_await(repo.list_all(
                status=status,
                severity=severity,
                assignee_id=assignee_id,
                reporter_id=reporter_id,
            )) or []

        # Fallback: filter in-memory store
        incidents = list(_IN_MEMORY_STORE.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        if assignee_id:
            incidents = [i for i in incidents if i.assignee_id == assignee_id]
        if reporter_id:
            incidents = [i for i in incidents if i.reporter_id == reporter_id]
        return incidents

    @staticmethod
    def update(incident_id: str, update: IncidentUpdate) -> Optional[Incident]:
        """Update an incident's fields. Returns updated incident or None if not found."""
        if not incident_id:
            return None

        repo = IncidentService._get_repository()
        if repo:
            inc = _maybe_await(repo.update(incident_id, update))
            if inc:
                _IN_MEMORY_STORE[incident_id] = inc
                logger.info("Incident %s updated", incident_id)
            return inc

        # Fallback: update in-memory
        inc = _IN_MEMORY_STORE.get(incident_id)
        if not inc:
            return None

        update_data = update.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "tags" and value is not None:
                setattr(inc, key, value)
            elif value is not None:
                setattr(inc, key, value)

        inc.updated_at = _now()
        _IN_MEMORY_STORE[incident_id] = inc
        logger.info("Incident %s updated (in-memory)", incident_id)
        return inc

    @staticmethod
    def add_comment(
        incident_id: str,
        data: IncidentCommentCreate,
        author_id: str,
        author_name: str,
    ) -> Optional[Incident]:
        """Add a comment to an incident. Returns updated incident or None if not found."""
        if not incident_id or not author_id:
            return None

        comment = IncidentComment(
            id=str(uuid.uuid4()),
            author_id=author_id,
            author_name=author_name,
            body=data.body.strip(),
            created_at=_now(),
        )

        repo = IncidentService._get_repository()
        if repo:
            inc = _maybe_await(repo.add_comment(incident_id, comment))
            if inc:
                _IN_MEMORY_STORE[incident_id] = inc
                logger.info("Comment added to incident %s by %s", incident_id, author_id)
            return inc

        # Fallback: update in-memory
        inc = _IN_MEMORY_STORE.get(incident_id)
        if not inc:
            return None

        inc.comments.append(comment)
        inc.updated_at = _now()
        _IN_MEMORY_STORE[incident_id] = inc
        logger.info("Comment added to incident %s (in-memory)", incident_id)
        return inc

    @staticmethod
    def delete(incident_id: str) -> bool:
        """Delete an incident by ID. Returns True if deleted, False otherwise."""
        if not incident_id:
            return False

        repo = IncidentService._get_repository()
        deleted = False
        if repo:
            deleted = bool(_maybe_await(repo.delete(incident_id)))

        if incident_id in _IN_MEMORY_STORE:
            del _IN_MEMORY_STORE[incident_id]
            deleted = True

        if deleted:
            logger.info("Incident %s deleted", incident_id)
        return deleted

    @staticmethod
    def stats() -> dict:
        """Return summary statistics: counts by status, severity, etc."""
        repo = IncidentService._get_repository()
        if repo:
            return repo.stats()

        # Fallback: compute from memory
        incidents = list(_IN_MEMORY_STORE.values())
        if not incidents:
            return {
                "total": 0,
                "by_status": {},
                "by_severity": {},
                "open": 0,
                "resolved": 0,
                "false_positives": 0,
            }

        by_status = {s.value: 0 for s in IncidentStatus}
        by_severity = {s.value: 0 for s in IncidentSeverity}
        open_count = 0
        resolved_count = 0
        false_pos_count = 0

        for inc in incidents:
            by_status[inc.status.value] = by_status.get(inc.status.value, 0) + 1
            by_severity[inc.severity.value] = by_severity.get(inc.severity.value, 0) + 1
            if inc.status in (IncidentStatus.OPEN, IncidentStatus.TRIAGING, IncidentStatus.IN_PROGRESS):
                open_count += 1
            elif inc.status == IncidentStatus.RESOLVED:
                resolved_count += 1
            if inc.false_positive:
                false_pos_count += 1

        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "open": open_count,
            "resolved": resolved_count,
            "false_positives": false_pos_count,
        }