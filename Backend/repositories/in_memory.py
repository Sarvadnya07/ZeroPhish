"""
In-memory repository adapters for unit testing, development, and zero-dependency execution.
Thread-safe and fully compliant with repository Protocols.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
from webhooks.models import WebhookDelivery, WebhookSubscription

from .base import (
    AnalyticsRepository,
    CacheBackend,
    IncidentRepository,
    ScanResultRepository,
    UserRepository,
    WebhookRepository,
)

logger = logging.getLogger(__name__)

DEFAULT_SCAN_RESULT_LIMIT = 500


class InMemoryUserRepository:
    def __init__(self):
        self._users_by_id: Dict[str, UserInDB] = {}
        self._users_by_clerk_id: Dict[str, str] = {}
        self._users_by_email: Dict[str, str] = {}
        self._tokens: Dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def get_by_id(self, user_id: str) -> Optional[UserInDB]:
        async with self._lock:
            return self._users_by_id.get(user_id)

    async def get_by_clerk_id(self, clerk_user_id: str) -> Optional[UserInDB]:
        async with self._lock:
            uid = self._users_by_clerk_id.get(clerk_user_id)
            return self._users_by_id.get(uid) if uid else None

    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        async with self._lock:
            uid = self._users_by_email.get(email.lower().strip())
            return self._users_by_id.get(uid) if uid else None

    async def save(self, user: UserInDB) -> UserInDB:
        if not getattr(user, "id", None) or not getattr(user, "email", None):
            raise ValueError("user must have id and email")
        async with self._lock:
            self._users_by_id[user.id] = user
            if getattr(user, "clerk_user_id", None):
                self._users_by_clerk_id[user.clerk_user_id] = user.id
            self._users_by_email[user.email.lower().strip()] = user.id
            logger.debug("Saved user %s (in-memory)", user.id)
            return user

    async def list_all(self, role: Optional[UserRole] = None) -> List[UserInDB]:
        async with self._lock:
            users = list(self._users_by_id.values())
            if role:
                users = [u for u in users if u.role == role]
            return users

    async def update(self, user_id: str, update: UserUpdate) -> Optional[UserInDB]:
        async with self._lock:
            user = self._users_by_id.get(user_id)
            if not user:
                return None
            if update.full_name is not None:
                user.full_name = update.full_name
            if update.role is not None:
                user.role = update.role
            if update.status is not None:
                user.status = update.status
            logger.debug("Updated user %s (in-memory)", user_id)
            return user

    async def delete(self, user_id: str) -> bool:
        async with self._lock:
            user = self._users_by_id.pop(user_id, None)
            if user:
                self._users_by_email.pop(user.email.lower().strip(), None)
                logger.debug("Deleted user %s (in-memory)", user_id)
                return True
            return False

    async def store_token(self, token: str, user_id: str, expires_at: float) -> None:
        async with self._lock:
            self._tokens[token] = {"user_id": user_id, "expires_at": expires_at}
            logger.debug("Stored token for user %s (in-memory)", user_id)

    async def validate_token(self, token: str) -> Optional[UserInDB]:
        async with self._lock:
            record = self._tokens.get(token)
            if not record:
                return None
            if time.time() > record["expires_at"]:
                self._tokens.pop(token, None)
                return None
            return self._users_by_id.get(record["user_id"])

    async def revoke_token(self, token: str) -> None:
        async with self._lock:
            self._tokens.pop(token, None)
            logger.debug("Revoked token (in-memory)")

    async def increment_scan(self, user_id: str, final_score: float) -> None:
        async with self._lock:
            user = self._users_by_id.get(user_id)
            if not user:
                return
            user.scan_count += 1
            n = user.scan_count
            user.risk_score = ((user.risk_score * (n - 1)) + final_score) / n
            logger.debug("Incremented scan count for user %s (in-memory)", user_id)


class InMemoryIncidentRepository:
    def __init__(self):
        self._store: Dict[str, Incident] = {}
        self._lock = asyncio.Lock()

    async def save(self, incident: Incident) -> Incident:
        async with self._lock:
            if not getattr(incident, "id", None):
                raise ValueError("incident must have id")
            # Ensure datetime fields are timezone-aware datetimes
            if not getattr(incident, "created_at", None):
                incident.created_at = datetime.now(timezone.utc)
            self._store[incident.id] = incident
            logger.debug("Saved incident %s (in-memory)", incident.id)
            return incident

    async def get_by_id(self, incident_id: str) -> Optional[Incident]:
        async with self._lock:
            return self._store.get(incident_id)

    async def list_all(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Incident]:
        async with self._lock:
            items = list(self._store.values())
            if status:
                items = [i for i in items if i.status == status]
            if severity:
                items = [i for i in items if i.severity == severity]
            if assignee_id:
                items = [i for i in items if i.assignee_id == assignee_id]
            if reporter_id:
                items = [i for i in items if i.reporter_id == reporter_id]
            return sorted(items, key=lambda i: i.created_at, reverse=True)

    async def update(self, incident_id: str, update: IncidentUpdate) -> Optional[Incident]:
        async with self._lock:
            inc = self._store.get(incident_id)
            if not inc:
                return None
            now = datetime.now(timezone.utc)
            if update.title is not None:
                inc.title = update.title
            if update.description is not None:
                inc.description = update.description
            if update.severity is not None:
                inc.severity = update.severity
            if update.assignee_id is not None:
                inc.assignee_id = update.assignee_id
            if update.tags is not None:
                inc.tags = update.tags
            if update.false_positive is not None:
                inc.false_positive = update.false_positive
            if update.status is not None:
                inc.status = update.status
                if update.status in (
                    IncidentStatus.RESOLVED,
                    IncidentStatus.CLOSED,
                    IncidentStatus.FALSE_POS,
                ):
                    inc.resolved_at = now
            inc.updated_at = now
            logger.debug("Updated incident %s (in-memory)", incident_id)
            return inc

    async def add_comment(self, incident_id: str, comment: IncidentComment) -> Optional[Incident]:
        async with self._lock:
            inc = self._store.get(incident_id)
            if not inc:
                return None
            inc.comments.append(comment)
            inc.updated_at = datetime.now(timezone.utc)
            logger.debug("Added comment to incident %s (in-memory)", incident_id)
            return inc

    async def delete(self, incident_id: str) -> bool:
        async with self._lock:
            removed = self._store.pop(incident_id, None) is not None
            if removed:
                logger.debug("Deleted incident %s (in-memory)", incident_id)
            return removed

    async def stats(self) -> Dict[str, Any]:
        async with self._lock:
            items = list(self._store.values())
            return {
                "total": len(items),
                "open": sum(1 for i in items if i.status == IncidentStatus.OPEN),
                "triaging": sum(1 for i in items if i.status == IncidentStatus.TRIAGING),
                "in_progress": sum(1 for i in items if i.status == IncidentStatus.IN_PROGRESS),
                "resolved": sum(1 for i in items if i.status == IncidentStatus.RESOLVED),
                "false_positives": sum(1 for i in items if i.false_positive),
                "by_severity": {
                    s.value: sum(1 for i in items if i.severity == s) for s in IncidentSeverity
                },
            }


class InMemoryAnalyticsRepository:
    def __init__(self):
        self._scan_events: deque[Dict[str, Any]] = deque(maxlen=10_000)
        self._false_positives: Dict[str, FalsePositiveReport] = {}
        self._policy_rules: Dict[str, PolicyRule] = {}
        self._lock = asyncio.Lock()
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
            last_evaluated=datetime.now(timezone.utc),
        )

    async def record_scan_event(self, event: Dict[str, Any]) -> None:
        async with self._lock:
            self._scan_events.append(event)
            self._model_metrics.total_inferences += 1
            logger.debug("Recorded scan event %s (in-memory)", event.get("scan_id"))

    async def get_scan_events(self, limit: int = 10000) -> List[Dict[str, Any]]:
        async with self._lock:
            return list(self._scan_events)[-limit:]

    async def get_dashboard_summary(self) -> AdminDashboardSummary:
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        week_start = today_start - 6 * 86400

        async with self._lock:
            today_events = [e for e in self._scan_events if e.get("ts", 0) >= today_start]
            week_events = [e for e in self._scan_events if e.get("ts", 0) >= week_start]

        critical = sum(1 for e in today_events if e.get("verdict") == "CRITICAL")
        suspicious = sum(1 for e in today_events if e.get("verdict") == "SUSPICIOUS")
        safe = sum(1 for e in today_events if e.get("verdict") == "SAFE")
        avg_score = sum(e.get("final_score", 0) for e in today_events) / max(len(today_events), 1)

        domain_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            if e.get("verdict") in ("CRITICAL", "SUSPICIOUS"):
                domain_counts[e.get("sender_domain", "unknown")] += 1
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:10]

        sender_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            sender_counts[e.get("sender_domain", "unknown")] += 1
        top_senders = sorted(sender_counts.items(), key=lambda x: -x[1])[:10]

        return AdminDashboardSummary(
            total_scans_today=len(today_events),
            total_scans_week=len(week_events),
            critical_today=critical,
            suspicious_today=suspicious,
            safe_today=safe,
            avg_score_today=round(avg_score, 2),
            false_positives_pending=sum(
                1 for fp in self._false_positives.values() if not fp.reviewed
            ),
            open_incidents=0,
            circuit_breaker_state="closed",
            top_malicious_domains=[{"domain": d, "count": c} for d, c in top_domains],
            top_senders=[{"domain": d, "count": c} for d, c in top_senders],
            model_accuracy=self._model_metrics.accuracy,
        )

    async def get_threat_heatmap(self) -> List[ThreatHeatmapEntry]:
        grid: Dict[tuple, List[float]] = defaultdict(list)
        async with self._lock:
            for e in self._scan_events:
                grid[(e.get("day", 0), e.get("hour", 0))].append(e.get("final_score", 0.0))
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

    async def get_threat_feed(self, limit: int = 50) -> List[ThreatFeedItem]:
        async with self._lock:
            events = [e for e in self._scan_events if e.get("verdict") in ("CRITICAL", "SUSPICIOUS")]
            events = list(reversed(events))[:limit]
            return [
            ThreatFeedItem(
                id=e.get("scan_id", ""),
                timestamp=e.get("timestamp", ""),
                sender_domain=e.get("sender_domain", ""),
                subject_snippet=e.get("subject", ""),
                final_score=e.get("final_score", 0.0),
                verdict=e.get("verdict", "SAFE"),
                category=e.get("category", "General"),
                tier1_score=e.get("tier1_score"),
                tier2_score=e.get("tier2_score"),
                tier3_score=e.get("tier3_score"),
            )
            for e in events
        ]

    async def get_model_metrics(self) -> ModelMetrics:
        async with self._lock:
            return self._model_metrics

    async def update_model_metrics(self, fp_delta: int = 0, fn_delta: int = 0) -> None:
        async with self._lock:
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
            self._model_metrics.last_evaluated = datetime.now(timezone.utc)

    async def save_false_positive(self, report: FalsePositiveReport) -> FalsePositiveReport:
        async with self._lock:
            self._false_positives[report.id] = report
            logger.debug("Saved false positive %s (in-memory)", report.id)
            return report

    async def list_false_positives(self, reviewed: Optional[bool] = None) -> List[FalsePositiveReport]:
        async with self._lock:
            items = list(self._false_positives.values())
            if reviewed is not None:
                items = [i for i in items if i.reviewed == reviewed]
            return items

    async def review_false_positive(
        self, fp_id: str, reviewer_id: str, resolution: str
    ) -> Optional[FalsePositiveReport]:
        async with self._lock:
            fp = self._false_positives.get(fp_id)
            if not fp:
                return None
            fp.reviewed = True
            fp.reviewer_id = reviewer_id
            fp.resolution = resolution
            await self.update_model_metrics(fp_delta=1)
            logger.debug("Reviewed false positive %s (in-memory)", fp_id)
            return fp

    async def save_policy_rule(self, rule: PolicyRule) -> PolicyRule:
        async with self._lock:
            self._policy_rules[rule.id] = rule
            logger.debug("Saved policy rule %s (in-memory)", rule.id)
            return rule

    async def list_policy_rules(self) -> List[PolicyRule]:
        async with self._lock:
            return list(self._policy_rules.values())

    async def delete_policy_rule(self, rule_id: str) -> bool:
        async with self._lock:
            removed = self._policy_rules.pop(rule_id, None) is not None
            if removed:
                logger.debug("Deleted policy rule %s (in-memory)", rule_id)
            return removed


class InMemoryWebhookRepository:
    def __init__(self):
        self._subscriptions: Dict[str, WebhookSubscription] = {}
        self._delivery_log: deque[WebhookDelivery] = deque(maxlen=1000)
        self._lock = asyncio.Lock()

    async def save_subscription(self, subscription: WebhookSubscription) -> WebhookSubscription:
        async with self._lock:
            self._subscriptions[subscription.id] = subscription
            logger.debug("Saved webhook subscription %s (in-memory)", subscription.id)
            return subscription

    async def get_subscription(self, sub_id: str) -> Optional[WebhookSubscription]:
        async with self._lock:
            return self._subscriptions.get(sub_id)

    async def list_subscriptions(self, owner_id: Optional[str] = None) -> List[WebhookSubscription]:
        async with self._lock:
            subs = list(self._subscriptions.values())
            if owner_id:
                subs = [s for s in subs if s.owner_id == owner_id]
            return subs

    async def delete_subscription(self, sub_id: str, owner_id: Optional[str] = None) -> bool:
        async with self._lock:
            sub = self._subscriptions.get(sub_id)
            if not sub:
                return False
            if owner_id and sub.owner_id != owner_id:
                return False
            self._subscriptions.pop(sub_id, None)
            logger.debug("Deleted webhook subscription %s (in-memory)", sub_id)
            return True

    async def record_delivery(self, delivery: WebhookDelivery) -> None:
        async with self._lock:
            self._delivery_log.append(delivery)
            logger.debug("Recorded webhook delivery %s (in-memory)", delivery.id)

    async def get_delivery_log(self, limit: int = 100) -> List[WebhookDelivery]:
        async with self._lock:
            return list(self._delivery_log)[-limit:]


class InMemoryScanResultRepository:
    def __init__(self, limit: int = 500):
        self._scans: Dict[str, Any] = {}
        self._limit = limit or DEFAULT_SCAN_RESULT_LIMIT
        self._lock = asyncio.Lock()

    async def save(self, scan_id: str, scan_data: Any) -> None:
        async with self._lock:
            self._scans[scan_id] = scan_data
            while len(self._scans) > self._limit:
                oldest_key = next(iter(self._scans))
                self._scans.pop(oldest_key, None)
            logger.debug("Saved scan result %s (in-memory)", scan_id)

    async def get(self, scan_id: str) -> Optional[Any]:
        async with self._lock:
            return self._scans.get(scan_id)

    async def delete(self, scan_id: str) -> bool:
        async with self._lock:
            removed = self._scans.pop(scan_id, None) is not None
            if removed:
                logger.debug("Deleted scan result %s (in-memory)", scan_id)
            return removed

    async def list_all(self, limit: int = 100) -> List[Any]:
        async with self._lock:
            return list(self._scans.values())[-limit:]

    async def count(self) -> int:
        async with self._lock:
            return len(self._scans)

    async def count_pending(self) -> int:
        async with self._lock:
            return sum(1 for v in self._scans.values() if not getattr(v, "complete", False))


class InMemoryCacheBackend:
    def __init__(self, default_ttl: int = 300):
        self._store: Dict[str, tuple[float, str]] = {}
        self._default_ttl = default_ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at and time.time() > expires_at:
                self._store.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = time.time() + ttl if ttl else 0
        async with self._lock:
            self._store[key] = (expires_at, value)
            logger.debug("Cache set key=%s ttl=%s (in-memory)", key, ttl)

    async def delete(self, key: str) -> bool:
        async with self._lock:
            removed = self._store.pop(key, None) is not None
            if removed:
                logger.debug("Cache delete key=%s (in-memory)", key)
            return removed

    async def clear_prefix(self, prefix: str) -> int:
        async with self._lock:
            keys_to_del = [k for k in self._store if k.startswith(prefix)]
            for k in keys_to_del:
                self._store.pop(k, None)
            logger.debug("Cleared cache prefix=%s removed=%d (in-memory)", prefix, len(keys_to_del))
            return len(keys_to_del)

    async def get_stats(self) -> Dict[str, Any]:
        async with self._lock:
            return {
                "status": "connected",
                "backend": "in_memory",
                "keys_count": len(self._store),
            }
