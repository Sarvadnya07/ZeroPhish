"""
SQLAlchemy repository implementations for durable relational storage.
"""

from __future__ import annotations

import datetime as _dt
import json
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy.orm import Session  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - SQLAlchemy is optional in some environments
    Session = Any  # type: ignore[misc,assignment]

from models.gateway_models import GatewayScanResponse

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
            clerk_user_id=str(u.clerk_user_id) if u.clerk_user_id else str(u.id),
            email=str(u.email),
            full_name=str(u.full_name),
            role=UserRole(str(u.role)),
            status=UserStatus(str(u.status)),
            scan_count=int(u.scan_count or 0),
            risk_score=float(u.risk_score or 0.0),
            created_at=u.created_at,
            last_login=u.last_login,
        )

    def get_by_id(self, user_id: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.id == user_id).first()
            return self._to_user_in_db(u) if u else None

    def get_by_clerk_id(self, clerk_user_id: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.clerk_user_id == clerk_user_id).first()
            return self._to_user_in_db(u) if u else None

    def get_by_email(self, email: str) -> Optional[UserInDB]:
        with self._session_factory() as session:
            u = session.query(UserDB).filter(UserDB.email == email.lower().strip()).first()
            return self._to_user_in_db(u) if u else None

    def save(self, user: UserInDB) -> UserInDB:
        with self._session_factory() as session:
            existing = session.query(UserDB).filter(UserDB.id == user.id).first()
            if existing:
                existing.clerk_user_id = user.clerk_user_id
                existing.full_name = user.full_name
                existing.role = user.role.value
                existing.status = user.status.value
                existing.scan_count = user.scan_count
                existing.risk_score = user.risk_score
                existing.last_login = user.last_login
            else:
                db_user = UserDB(
                    id=user.id,
                    clerk_user_id=user.clerk_user_id,
                    email=user.email.lower().strip(),
                    full_name=user.full_name,
                    role=user.role.value,
                    status=user.status.value,
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
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            resolved_at=inc.resolved_at,
            comments=[
                IncidentComment(
                    id=str(c.id),
                    author_id=str(c.author_id),
                    author_name=str(c.author_name),
                    body=str(c.body),
                    created_at=c.created_at,
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


class SQLScanResultRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def save(self, scan_id: str, scan_data: Any) -> None:
        data_dict = scan_data.model_dump() if hasattr(scan_data, "model_dump") else scan_data
        data_json = json.dumps(data_dict)
        final_score = getattr(scan_data, "final_score", None)
        partial_score = float(getattr(scan_data, "partial_score", 0.0) or 0.0)
        verdict = str(getattr(scan_data, "verdict", "SAFE"))
        complete = bool(getattr(scan_data, "complete", False))
        layers_completed = int(getattr(scan_data, "layers_completed", 0) or 0)
        ts_str = str(getattr(scan_data, "timestamp", _dt.datetime.now(_dt.timezone.utc).isoformat()))

        with self._session_factory() as session:
            existing = session.query(ScanResultDB).filter(ScanResultDB.scan_id == scan_id).first()
            if existing:
                existing.partial_score = partial_score
                existing.final_score = final_score
                existing.verdict = verdict
                existing.complete = complete
                existing.layers_completed = layers_completed
                existing.data_json = data_json
            else:
                db_record = ScanResultDB(
                    scan_id=scan_id,
                    timestamp=ts_str,
                    partial_score=partial_score,
                    final_score=final_score,
                    verdict=verdict,
                    complete=complete,
                    layers_completed=layers_completed,
                    data_json=data_json,
                    created_at=time.time(),
                )
                session.add(db_record)
            session.commit()

    def get(self, scan_id: str) -> Optional[Any]:
        with self._session_factory() as session:
            row = session.query(ScanResultDB).filter(ScanResultDB.scan_id == scan_id).first()
            if not row or not row.data_json:
                return None
            try:
                parsed = json.loads(row.data_json)
                return GatewayScanResponse.model_validate(parsed)
            except Exception:
                return None

    def delete(self, scan_id: str) -> bool:
        with self._session_factory() as session:
            row = session.query(ScanResultDB).filter(ScanResultDB.scan_id == scan_id).first()
            if row:
                session.delete(row)
                session.commit()
                return True
            return False

    def list_all(self, limit: int = 100) -> List[Any]:
        with self._session_factory() as session:
            rows = (
                session.query(ScanResultDB)
                .order_by(ScanResultDB.created_at.desc())
                .limit(limit)
                .all()
            )
            results = []
            for r in rows:
                try:
                    results.append(GatewayScanResponse.model_validate(json.loads(r.data_json)))
                except Exception:
                    continue
            return results

    def count(self) -> int:
        with self._session_factory() as session:
            return session.query(ScanResultDB).count()

    def count_pending(self) -> int:
        with self._session_factory() as session:
            return session.query(ScanResultDB).filter(ScanResultDB.complete == False).count()


class SQLAnalyticsRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory
        self._model_metrics = ModelMetrics(
            model_id="cybersectony/phishing-email-detection-distilbert_v2.1",
            accuracy=0.972,
            precision=0.968,
            recall=0.975,
            f1=0.971,
            total_inferences=0,
            avg_latency_ms=320.0,
            false_positive_rate=0.032,
            false_negative_rate=0.025,
            last_evaluated=_dt.datetime.utcnow(),
        )

    def record_scan_event(self, event: Dict[str, Any]) -> None:
        with self._session_factory() as session:
            ev = ScanEventDB(
                scan_id=str(event.get("scan_id", "")),
                timestamp=str(event.get("timestamp", "")),
                ts=float(event.get("ts", time.time())),
                hour=int(event.get("hour", 0)),
                day=int(event.get("day", 0)),
                sender_domain=str(event.get("sender_domain", "unknown")),
                subject=str(event.get("subject", ""))[:500] if event.get("subject") else None,
                final_score=float(event.get("final_score", 0.0)),
                verdict=str(event.get("verdict", "SAFE")),
                category=str(event.get("category", "General")),
                tier1_score=float(event.get("tier1_score", 0.0)),
                tier2_score=float(event.get("tier2_score", 0.0)),
                tier3_score=float(event.get("tier3_score", 0.0)),
                user_id=str(event.get("user_id")) if event.get("user_id") else None,
            )
            session.add(ev)
            session.commit()
        self._model_metrics.total_inferences += 1

    def get_scan_events(self, limit: int = 10000) -> List[Dict[str, Any]]:
        with self._session_factory() as session:
            rows = session.query(ScanEventDB).order_by(ScanEventDB.id.desc()).limit(limit).all()
            return [
                {
                    "scan_id": r.scan_id,
                    "timestamp": r.timestamp,
                    "ts": r.ts,
                    "hour": r.hour,
                    "day": r.day,
                    "sender_domain": r.sender_domain,
                    "subject": r.subject,
                    "final_score": r.final_score,
                    "verdict": r.verdict,
                    "category": r.category,
                    "tier1_score": r.tier1_score,
                    "tier2_score": r.tier2_score,
                    "tier3_score": r.tier3_score,
                    "user_id": r.user_id,
                }
                for r in reversed(rows)
            ]

    def get_dashboard_summary(self) -> AdminDashboardSummary:
        now = _dt.datetime.now(_dt.timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        week_start = today_start - 6 * 86400

        with self._session_factory() as session:
            today_events = (
                session.query(ScanEventDB).filter(ScanEventDB.ts >= today_start).all()
            )
            week_events = (
                session.query(ScanEventDB).filter(ScanEventDB.ts >= week_start).all()
            )
            pending_fp = (
                session.query(FalsePositiveDB).filter(FalsePositiveDB.reviewed == False).count()
            )

        critical = sum(1 for e in today_events if e.verdict == "CRITICAL")
        suspicious = sum(1 for e in today_events if e.verdict == "SUSPICIOUS")
        safe = sum(1 for e in today_events if e.verdict == "SAFE")
        avg_score = (
            sum(e.final_score for e in today_events) / max(len(today_events), 1)
        )

        domain_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            if e.verdict in ("CRITICAL", "SUSPICIOUS"):
                domain_counts[e.sender_domain] += 1
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:10]

        sender_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            sender_counts[e.sender_domain] += 1
        top_senders = sorted(sender_counts.items(), key=lambda x: -x[1])[:10]

        return AdminDashboardSummary(
            total_scans_today=len(today_events),
            total_scans_week=len(week_events),
            critical_today=critical,
            suspicious_today=suspicious,
            safe_today=safe,
            avg_score_today=round(avg_score, 2),
            false_positives_pending=pending_fp,
            open_incidents=0,
            circuit_breaker_state="closed",
            top_malicious_domains=[{"domain": d, "count": c} for d, c in top_domains],
            top_senders=[{"domain": d, "count": c} for d, c in top_senders],
            model_accuracy=self._model_metrics.accuracy,
        )

    def get_threat_heatmap(self) -> List[ThreatHeatmapEntry]:
        with self._session_factory() as session:
            events = session.query(ScanEventDB.day, ScanEventDB.hour, ScanEventDB.final_score).all()

        grid: Dict[tuple, List[float]] = defaultdict(list)
        for day, hour, score in events:
            grid[(day, hour)].append(score)

        result = []
        for (day, hour), scores in grid.items():
            result.append(
                ThreatHeatmapEntry(
                    day=day,
                    hour=hour,
                    count=len(scores),
                    avg_score=round(sum(scores) / len(scores), 2),
                )
            )
        existing = {(r.day, r.hour) for r in result}
        for d in range(7):
            for h in range(24):
                if (d, h) not in existing:
                    result.append(ThreatHeatmapEntry(day=d, hour=h, count=0, avg_score=0.0))
        return sorted(result, key=lambda x: (x.day, x.hour))

    def get_threat_feed(self, limit: int = 50) -> List[ThreatFeedItem]:
        with self._session_factory() as session:
            rows = (
                session.query(ScanEventDB)
                .filter(ScanEventDB.verdict.in_(["CRITICAL", "SUSPICIOUS"]))
                .order_by(ScanEventDB.id.desc())
                .limit(limit)
                .all()
            )
            return [
                ThreatFeedItem(
                    id=r.scan_id,
                    timestamp=r.timestamp,
                    sender_domain=r.sender_domain,
                    subject_snippet=r.subject or "",
                    final_score=r.final_score,
                    verdict=r.verdict,
                    category=r.category,
                    tier1_score=r.tier1_score,
                    tier2_score=r.tier2_score,
                    tier3_score=r.tier3_score,
                )
                for r in rows
            ]

    def get_model_metrics(self) -> ModelMetrics:
        return self._model_metrics

    def update_model_metrics(self, fp_delta: int = 0, fn_delta: int = 0) -> None:
        n = max(self._model_metrics.total_inferences, 1)
        if fp_delta:
            self._model_metrics.false_positive_rate = min(
                1.0, self._model_metrics.false_positive_rate + fp_delta / n
            )
        if fn_delta:
            self._model_metrics.false_negative_rate = min(
                1.0, self._model_metrics.false_negative_rate + fn_delta / n
            )
        self._model_metrics.accuracy = max(
            0.0,
            1.0 - self._model_metrics.false_positive_rate - self._model_metrics.false_negative_rate,
        )
        self._model_metrics.last_evaluated = _dt.datetime.utcnow()

    def save_false_positive(self, report: FalsePositiveReport) -> FalsePositiveReport:
        with self._session_factory() as session:
            existing = session.query(FalsePositiveDB).filter(FalsePositiveDB.id == report.id).first()
            if existing:
                existing.reviewed = report.reviewed
                existing.reviewer_id = report.reviewer_id
                existing.resolution = report.resolution
            else:
                row = FalsePositiveDB(
                    id=report.id,
                    scan_id=report.scan_id,
                    reporter_id=report.reporter_id,
                    reason=report.reason,
                    original_score=report.original_score,
                    original_verdict=report.original_verdict,
                    reviewed=report.reviewed,
                    reviewer_id=report.reviewer_id,
                    resolution=report.resolution,
                    created_at=report.created_at,
                )
                session.add(row)
            session.commit()
            return report

    def list_false_positives(self, reviewed: Optional[bool] = None) -> List[FalsePositiveReport]:
        with self._session_factory() as session:
            query = session.query(FalsePositiveDB)
            if reviewed is not None:
                query = query.filter(FalsePositiveDB.reviewed == reviewed)
            rows = query.order_by(FalsePositiveDB.created_at.desc()).all()
            return [
                FalsePositiveReport(
                    id=r.id,
                    scan_id=r.scan_id,
                    reporter_id=r.reporter_id,
                    reason=r.reason,
                    original_score=r.original_score,
                    original_verdict=r.original_verdict,
                    reviewed=r.reviewed,
                    reviewer_id=r.reviewer_id,
                    resolution=r.resolution,
                    created_at=r.created_at,
                )
                for r in rows
            ]

    def review_false_positive(
        self, fp_id: str, reviewer_id: str, resolution: str
    ) -> Optional[FalsePositiveReport]:
        with self._session_factory() as session:
            row = session.query(FalsePositiveDB).filter(FalsePositiveDB.id == fp_id).first()
            if not row:
                return None
            row.reviewed = True
            row.reviewer_id = reviewer_id
            row.resolution = resolution
            session.commit()
            self.update_model_metrics(fp_delta=1)
            return FalsePositiveReport(
                id=row.id,
                scan_id=row.scan_id,
                reporter_id=row.reporter_id,
                reason=row.reason,
                original_score=row.original_score,
                original_verdict=row.original_verdict,
                reviewed=row.reviewed,
                reviewer_id=row.reviewer_id,
                resolution=row.resolution,
                created_at=row.created_at,
            )

    def save_policy_rule(self, rule: PolicyRule) -> PolicyRule:
        with self._session_factory() as session:
            existing = session.query(PolicyRuleDB).filter(PolicyRuleDB.id == rule.id).first()
            if existing:
                existing.name = rule.name
                existing.description = rule.description
                existing.enabled = rule.enabled
                existing.condition_type = rule.condition_type
                existing.condition_value = rule.condition_value
                existing.action = rule.action
            else:
                row = PolicyRuleDB(
                    id=rule.id,
                    name=rule.name,
                    description=rule.description,
                    enabled=rule.enabled,
                    condition_type=rule.condition_type,
                    condition_value=rule.condition_value,
                    action=rule.action,
                    created_by=rule.created_by,
                    created_at=rule.created_at,
                )
                session.add(row)
            session.commit()
            return rule

    def list_policy_rules(self) -> List[PolicyRule]:
        with self._session_factory() as session:
            rows = session.query(PolicyRuleDB).all()
            return [
                PolicyRule(
                    id=r.id,
                    name=r.name,
                    description=r.description,
                    enabled=r.enabled,
                    condition_type=r.condition_type,
                    condition_value=r.condition_value,
                    action=r.action,
                    created_by=r.created_by,
                    created_at=r.created_at,
                )
                for r in rows
            ]

    def delete_policy_rule(self, rule_id: str) -> bool:
        with self._session_factory() as session:
            row = session.query(PolicyRuleDB).filter(PolicyRuleDB.id == rule_id).first()
            if row:
                session.delete(row)
                session.commit()
                return True
            return False


class SQLWebhookRepository:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def save_subscription(self, subscription: WebhookSubscription) -> WebhookSubscription:
        events_json = json.dumps([e.value if hasattr(e, "value") else str(e) for e in subscription.events])
        headers_json = json.dumps(subscription.headers)
        with self._session_factory() as session:
            existing = (
                session.query(WebhookSubscriptionDB)
                .filter(WebhookSubscriptionDB.id == subscription.id)
                .first()
            )
            if existing:
                existing.url = subscription.url
                existing.events_json = events_json
                existing.secret = subscription.secret
                existing.enabled = subscription.enabled
                existing.owner_id = subscription.owner_id
                existing.description = subscription.description
                existing.headers_json = headers_json
            else:
                row = WebhookSubscriptionDB(
                    id=subscription.id,
                    url=subscription.url,
                    events_json=events_json,
                    secret=subscription.secret,
                    enabled=subscription.enabled,
                    owner_id=subscription.owner_id,
                    description=subscription.description,
                    headers_json=headers_json,
                    created_at=subscription.created_at,
                )
                session.add(row)
            session.commit()
            return subscription

    def get_subscription(self, sub_id: str) -> Optional[WebhookSubscription]:
        with self._session_factory() as session:
            r = session.query(WebhookSubscriptionDB).filter(WebhookSubscriptionDB.id == sub_id).first()
            if not r:
                return None
            return WebhookSubscription(
                id=r.id,
                url=r.url,
                events=json.loads(r.events_json or "[]"),
                secret=r.secret,
                enabled=r.enabled,
                created_at=r.created_at,
                owner_id=r.owner_id,
                description=r.description,
                headers=json.loads(r.headers_json or "{}"),
            )

    def list_subscriptions(self, owner_id: Optional[str] = None) -> List[WebhookSubscription]:
        with self._session_factory() as session:
            query = session.query(WebhookSubscriptionDB)
            if owner_id:
                query = query.filter(WebhookSubscriptionDB.owner_id == owner_id)
            rows = query.all()
            return [
                WebhookSubscription(
                    id=r.id,
                    url=r.url,
                    events=json.loads(r.events_json or "[]"),
                    secret=r.secret,
                    enabled=r.enabled,
                    created_at=r.created_at,
                    owner_id=r.owner_id,
                    description=r.description,
                    headers=json.loads(r.headers_json or "{}"),
                )
                for r in rows
            ]

    def delete_subscription(self, sub_id: str, owner_id: Optional[str] = None) -> bool:
        with self._session_factory() as session:
            r = session.query(WebhookSubscriptionDB).filter(WebhookSubscriptionDB.id == sub_id).first()
            if not r:
                return False
            if owner_id and r.owner_id != owner_id:
                return False
            session.delete(r)
            session.commit()
            return True

    def record_delivery(self, delivery: WebhookDelivery) -> None:
        with self._session_factory() as session:
            row = WebhookDeliveryDB(
                id=delivery.id,
                subscription_id=delivery.subscription_id,
                event_type=delivery.event_type.value if hasattr(delivery.event_type, "value") else str(delivery.event_type),
                payload_json=json.dumps(delivery.payload),
                status=delivery.status,
                http_status=delivery.http_status,
                response_body=delivery.response_body,
                attempted_at=delivery.attempted_at,
                duration_ms=delivery.duration_ms,
                retries=delivery.retries,
            )
            session.add(row)
            session.commit()

    def get_delivery_log(self, limit: int = 100) -> List[WebhookDelivery]:
        with self._session_factory() as session:
            rows = (
                session.query(WebhookDeliveryDB)
                .order_by(WebhookDeliveryDB.attempted_at.desc())
                .limit(limit)
                .all()
            )
            return [
                WebhookDelivery(
                    id=r.id,
                    subscription_id=r.subscription_id,
                    event_type=r.event_type,
                    payload=json.loads(r.payload_json or "{}"),
                    status=r.status,
                    http_status=r.http_status,
                    response_body=r.response_body,
                    attempted_at=r.attempted_at,
                    duration_ms=r.duration_ms,
                    retries=r.retries or 0,
                )
                for r in rows
            ]
