"""
SQLAlchemy repository implementations for durable relational storage.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from analytics.models import (
    AdminDashboardSummary,
    FalsePositiveReport,
    ModelMetrics,
    PolicyRule,
    ThreatFeedItem,
    ThreatHeatmapEntry,
)
from auth.models import User, UserInDB, UserRole, UserStatus, UserUpdate
from incidents.models import (
    Incident,
    IncidentComment,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdate,
)
from infrastructure.models import (
    FalsePositiveDB,
    IncidentCommentDB,
    IncidentDB,
    PolicyRuleDB,
    ScanEventDB,
    ScanResultDB,
    TokenRevocationDB,
    UserDB,
    WebhookDeliveryDB,
    WebhookSubscriptionDB,
)
from webhooks.models import WebhookDelivery, WebhookSubscription


class SQLUserRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def _to_user_in_db(self, u: UserDB) -> UserInDB:
        return UserInDB(
            id=str(u.id),
            email=str(u.email),
            full_name=str(u.full_name),
            password_hash=str(u.password_hash),
            role=UserRole(str(u.role)),
            status=UserStatus(str(u.status)),
            mfa_secret=str(u.mfa_secret) if u.mfa_secret else None,
            mfa_enabled=bool(u.mfa_enabled),
            scan_count=int(u.scan_count or 0),
            risk_score=float(u.risk_score or 0.0),
            created_at=str(u.created_at),
            last_login=str(u.last_login) if u.last_login else None,
        )

    def get_by_id(self, user_id: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.id == user_id).first()
            return self._to_user_in_db(u) if u else None

    def get_by_email(self, email: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.email == email.lower().strip()).first()
            return self._to_user_in_db(u) if u else None

    def save(self, user: UserInDB) -> UserInDB:
        with self._session_factory() as session:
            existing = session.query(UserDB).filter(UserDB.id == user.id).first()
            if existing:
                existing.full_name = user.full_name
                existing.password_hash = user.password_hash
                existing.role = user.role.value
                existing.status = user.status.value
                existing.mfa_secret = user.mfa_secret
                existing.mfa_enabled = user.mfa_enabled
                existing.scan_count = user.scan_count
                existing.risk_score = user.risk_score
                existing.last_login = user.last_login
            else:
                db_user = UserDB(
                    id=user.id,
                    email=user.email.lower().strip(),
                    full_name=user.full_name,
                    password_hash=user.password_hash,
                    role=user.role.value,
                    status=user.status.value,
                    mfa_secret=user.mfa_secret,
                    mfa_enabled=user.mfa_enabled,
                    scan_count=user.scan_count,
                    risk_score=user.risk_score,
                    created_at=user.created_at,
                    last_login=user.last_login,
                )
                session.add(db_user)
            session.commit()
            return user

    def list_all(self, role: Optional[UserRole] = None) -> List[UserInDB]:
        with self._session_factory() as session:
            q = session.query(UserDB)
            if role:
                q = q.filter(UserDB.role == role.value)
            return [self._to_user_in_db(u) for u in q.all()]

    def update(self, user_id: str, update: UserUpdate) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.id == user_id).first()
            if not u:
                return None
            if update.full_name is not None:
                u.full_name = update.full_name
            if update.role is not None:
                u.role = update.role.value
            if update.status is not None:
                u.status = update.status.value
            session.commit()
            return self._to_user_in_db(u)

    def delete(self, user_id: str) -> bool:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.id == user_id).first()
            if u:
                session.delete(u)
                session.commit()
                return True
            return False

    def store_token(self, token: str, user_id: str, expires_at: float) -> None:
        with self._session_factory() as session:
            rec = TokenRevocationDB(token=token, user_id=user_id, expires_at=expires_at)
            session.merge(rec)
            session.commit()

    def validate_token(self, token: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            rec = session.query(TokenRevocationDB).filter(TokenRevocationDB.token == token).first()
            if not rec:
                return None
            if time.time() > rec.expires_at:
                session.delete(rec)
                session.commit()
                return None
            u = session.query(UserDB).filter(UserDB.id == rec.user_id).first()
            return self._to_user_in_db(u) if u else None

    def revoke_token(self, token: str) -> None:
        with self._session_factory() as session:
            rec = session.query(TokenRevocationDB).filter(TokenRevocationDB.token == token).first()
            if rec:
                session.delete(rec)
                session.commit()

    def increment_scan(self, user_id: str, final_score: float) -> None:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.id == user_id).first()
            if not u:
                return
            u.scan_count += 1
            n = u.scan_count
            u.risk_score = ((u.risk_score * (n - 1)) + final_score) / n
            session.commit()


class SQLIncidentRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def _to_incident(self, inc: IncidentDB) -> Incident:
        return Incident(
            id=str(inc.id),
            title=str(inc.title),
            description=str(inc.description),
            severity=IncidentSeverity(str(inc.severity)),
            status=IncidentStatus(str(inc.status)),
            scan_id=str(inc.scan_id) if inc.scan_id else None,
            reporter_id=str(inc.reporter_id) if inc.reporter_id else None,
            assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
            final_score=float(inc.final_score) if inc.final_score is not None else None,
            sender=str(inc.sender) if inc.sender else None,
            subject=str(inc.subject) if inc.subject else None,
            evidence=json.loads(str(inc.evidence_json) if inc.evidence_json else "[]"),
            tags=json.loads(str(inc.tags_json) if inc.tags_json else "[]"),
            false_positive=bool(inc.false_positive),
            created_at=str(inc.created_at),
            updated_at=str(inc.updated_at),
            resolved_at=str(inc.resolved_at) if inc.resolved_at else None,
            comments=[
                IncidentComment(
                    id=str(c.id),
                    author_id=str(c.author_id),
                    author_name=str(c.author_name),
                    body=str(c.body),
                    created_at=str(c.created_at),
                )
                for c in (inc.comments or [])
            ],
        )

    def save(self, incident: Incident) -> Incident:
        with self._session_factory() as session:
            db_inc = IncidentDB(
                id=incident.id,
                title=incident.title,
                description=incident.description,
                severity=incident.severity.value,
                status=incident.status.value,
                scan_id=incident.scan_id,
                reporter_id=incident.reporter_id,
                assignee_id=incident.assignee_id,
                final_score=incident.final_score,
                sender=incident.sender,
                subject=incident.subject,
                evidence_json=json.dumps(incident.evidence),
                tags_json=json.dumps(incident.tags),
                false_positive=incident.false_positive,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                resolved_at=incident.resolved_at,
            )
            session.merge(db_inc)
            session.commit()
            return incident

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        with self._session_factory() as session:
            inc = session.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
            return self._to_incident(inc) if inc else None

    def list_all(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Incident]:
        with self._session_factory() as session:
            q = session.query(IncidentDB)
            if status:
                q = q.filter(IncidentDB.status == status.value)
            if severity:
                q = q.filter(IncidentDB.severity == severity.value)
            if assignee_id:
                q = q.filter(IncidentDB.assignee_id == assignee_id)
            if reporter_id:
                q = q.filter(IncidentDB.reporter_id == reporter_id)
            items = q.order_by(IncidentDB.created_at.desc()).all()
            return [self._to_incident(i) for i in items]

    def update(self, incident_id: str, update: IncidentUpdate) -> Optional[Incident]:
        with self._session_factory() as session:
            inc = session.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
            if not inc:
                return None
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if update.title is not None:
                inc.title = update.title
            if update.description is not None:
                inc.description = update.description
            if update.severity is not None:
                inc.severity = update.severity.value
            if update.assignee_id is not None:
                inc.assignee_id = update.assignee_id
            if update.tags is not None:
                inc.tags_json = json.dumps(update.tags)
            if update.false_positive is not None:
                inc.false_positive = update.false_positive
            if update.status is not None:
                inc.status = update.status.value
                if update.status in (
                    IncidentStatus.RESOLVED,
                    IncidentStatus.CLOSED,
                    IncidentStatus.FALSE_POS,
                ):
                    inc.resolved_at = now
            inc.updated_at = now
            session.commit()
            return self._to_incident(inc)

    def add_comment(self, incident_id: str, comment: IncidentComment) -> Optional[Incident]:
        with self._session_factory() as session:
            inc = session.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
            if not inc:
                return None
            c = IncidentCommentDB(
                id=comment.id,
                incident_id=incident_id,
                author_id=comment.author_id,
                author_name=comment.author_name,
                body=comment.body,
                created_at=comment.created_at,
            )
            session.add(c)
            inc.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            session.commit()
            return self._to_incident(inc)

    def delete(self, incident_id: str) -> bool:
        with self._session_factory() as session:
            inc = session.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
            if inc:
                session.delete(inc)
                session.commit()
                return True
            return False

    def stats(self) -> Dict[str, Any]:
        with self._session_factory() as session:
            items = session.query(IncidentDB).all()
            return {
                "total": len(items),
                "open": sum(1 for i in items if i.status == IncidentStatus.OPEN.value),
                "triaging": sum(1 for i in items if i.status == IncidentStatus.TRIAGING.value),
                "in_progress": sum(
                    1 for i in items if i.status == IncidentStatus.IN_PROGRESS.value
                ),
                "resolved": sum(1 for i in items if i.status == IncidentStatus.RESOLVED.value),
                "false_positives": sum(1 for i in items if i.false_positive),
                "by_severity": {
                    s.value: sum(1 for i in items if i.severity == s.value)
                    for s in IncidentSeverity
                },
            }
