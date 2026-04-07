"""
Analytics & Policy service — in-memory scan telemetry, heatmaps, threat feed,
model metrics, false-positive review, and policy rule engine.
"""
from __future__ import annotations

import random
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from .models import (
    AdminDashboardSummary,
    FalsePositiveReport,
    ModelMetrics,
    PolicyRule,
    PolicyRuleCreate,
    ThreatFeedItem,
    ThreatHeatmapEntry,
)

# ── Telemetry store ────────────────────────────────────────────────────────────
_scan_events: deque[Dict[str, Any]] = deque(maxlen=10_000)
_false_positives: Dict[str, FalsePositiveReport] = {}
_policy_rules: Dict[str, PolicyRule] = {}

_SEED_MODEL_METRICS = ModelMetrics(
    model_id="cybersectony/phishing-email-detection-distilbert_v2.1",
    accuracy=0.972,
    precision=0.968,
    recall=0.975,
    f1=0.971,
    total_inferences=0,
    avg_latency_ms=320.0,
    false_positive_rate=0.032,
    false_negative_rate=0.025,
    last_evaluated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
)
_model_metrics = _SEED_MODEL_METRICS.model_copy()


class AnalyticsService:

    # ── Telemetry ingestion ───────────────────────────────────────────────────

    @staticmethod
    def record_scan(
        scan_id: str,
        sender: str,
        subject: str,
        final_score: float,
        verdict: str,
        category: str,
        tier1: float = 0,
        tier2: float = 0,
        tier3: float = 0,
    ) -> None:
        ts = time.time()
        import datetime as _dt
        dt = _dt.datetime.utcnow()
        _scan_events.append({
            "scan_id": scan_id,
            "timestamp": dt.isoformat() + "Z",
            "ts": ts,
            "hour": dt.hour,
            "day": dt.weekday(),
            "sender_domain": sender.split("@")[-1] if "@" in sender else sender,
            "subject": subject[:80],
            "final_score": final_score,
            "verdict": verdict,
            "category": category,
            "tier1_score": tier1,
            "tier2_score": tier2,
            "tier3_score": tier3,
        })
        _model_metrics.total_inferences += 1

    # ── Dashboard summary ─────────────────────────────────────────────────────

    @staticmethod
    def dashboard_summary() -> AdminDashboardSummary:
        import datetime as _dt
        now = _dt.datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        week_start  = today_start - 6 * 86400

        today_events = [e for e in _scan_events if e["ts"] >= today_start]
        week_events  = [e for e in _scan_events if e["ts"] >= week_start]

        critical    = sum(1 for e in today_events if e["verdict"] == "CRITICAL")
        suspicious  = sum(1 for e in today_events if e["verdict"] == "SUSPICIOUS")
        safe        = sum(1 for e in today_events if e["verdict"] == "SAFE")
        avg_score   = sum(e["final_score"] for e in today_events) / max(len(today_events), 1)

        # Top malicious domains
        domain_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            if e["verdict"] in ("CRITICAL", "SUSPICIOUS"):
                domain_counts[e["sender_domain"]] += 1
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:10]

        # Top senders (by volume)
        sender_counts: Dict[str, int] = defaultdict(int)
        for e in week_events:
            sender_counts[e["sender_domain"]] += 1
        top_senders = sorted(sender_counts.items(), key=lambda x: -x[1])[:10]

        from incidents.service import IncidentService
        from incidents.models import IncidentStatus
        inc_stats = IncidentService.stats()

        return AdminDashboardSummary(
            total_scans_today=len(today_events),
            total_scans_week=len(week_events),
            critical_today=critical,
            suspicious_today=suspicious,
            safe_today=safe,
            avg_score_today=round(avg_score, 2),
            false_positives_pending=sum(1 for fp in _false_positives.values() if not fp.reviewed),
            open_incidents=inc_stats.get("open", 0),
            circuit_breaker_state="closed",  # real value pulled from gateway
            top_malicious_domains=[{"domain": d, "count": c} for d, c in top_domains],
            top_senders=[{"domain": d, "count": c} for d, c in top_senders],
            model_accuracy=_model_metrics.accuracy,
        )

    # ── Heatmap ───────────────────────────────────────────────────────────────

    @staticmethod
    def threat_heatmap() -> List[ThreatHeatmapEntry]:
        grid: Dict[tuple, List[float]] = defaultdict(list)
        for e in _scan_events:
            grid[(e["day"], e["hour"])].append(e["final_score"])
        result = []
        for (day, hour), scores in grid.items():
            result.append(ThreatHeatmapEntry(
                day=day, hour=hour,
                count=len(scores),
                avg_score=round(sum(scores) / len(scores), 2),
            ))
        # Fill missing slots with zeros for full 7×24 grid
        existing = {(r.day, r.hour) for r in result}
        for d in range(7):
            for h in range(24):
                if (d, h) not in existing:
                    result.append(ThreatHeatmapEntry(day=d, hour=h, count=0, avg_score=0.0))
        return sorted(result, key=lambda x: (x.day, x.hour))

    # ── Threat feed ──────────────────────────────────────────────────────────

    @staticmethod
    def threat_feed(limit: int = 50) -> List[ThreatFeedItem]:
        events = [e for e in _scan_events if e["verdict"] in ("CRITICAL", "SUSPICIOUS")]
        events = list(reversed(events))[:limit]
        return [
            ThreatFeedItem(
                id=e["scan_id"],
                timestamp=e["timestamp"],
                sender_domain=e["sender_domain"],
                subject_snippet=e["subject"],
                final_score=e["final_score"],
                verdict=e["verdict"],
                category=e["category"],
                tier1_score=e.get("tier1_score"),
                tier2_score=e.get("tier2_score"),
                tier3_score=e.get("tier3_score"),
            )
            for e in events
        ]

    # ── Model metrics ────────────────────────────────────────────────────────

    @staticmethod
    def model_metrics() -> ModelMetrics:
        return _model_metrics

    @staticmethod
    def update_model_metrics(fp_delta: int = 0, fn_delta: int = 0) -> None:
        n = max(_model_metrics.total_inferences, 1)
        if fp_delta:
            _model_metrics.false_positive_rate = min(
                1.0, _model_metrics.false_positive_rate + fp_delta / n
            )
        if fn_delta:
            _model_metrics.false_negative_rate = min(
                1.0, _model_metrics.false_negative_rate + fn_delta / n
            )
        # Recalculate accuracy from rates
        _model_metrics.accuracy = max(
            0.0,
            1.0 - _model_metrics.false_positive_rate - _model_metrics.false_negative_rate,
        )
        _model_metrics.last_evaluated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # ── False-positive review ────────────────────────────────────────────────

    @staticmethod
    def report_false_positive(
        scan_id: str,
        reporter_id: str,
        reason: str,
        original_score: float,
        original_verdict: str,
    ) -> FalsePositiveReport:
        fp = FalsePositiveReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            reporter_id=reporter_id,
            reason=reason,
            original_score=original_score,
            original_verdict=original_verdict,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        _false_positives[fp.id] = fp
        return fp

    @staticmethod
    def list_false_positives(reviewed: Optional[bool] = None) -> List[FalsePositiveReport]:
        items = list(_false_positives.values())
        if reviewed is not None:
            items = [i for i in items if i.reviewed == reviewed]
        return items

    @staticmethod
    def review_false_positive(fp_id: str, reviewer_id: str, resolution: str) -> Optional[FalsePositiveReport]:
        fp = _false_positives.get(fp_id)
        if not fp:
            return None
        fp.reviewed = True
        fp.reviewer_id = reviewer_id
        fp.resolution = resolution
        AnalyticsService.update_model_metrics(fp_delta=1)
        return fp

    # ── Policy rules ─────────────────────────────────────────────────────────

    @staticmethod
    def create_policy(data: PolicyRuleCreate, creator_id: str) -> PolicyRule:
        rule = PolicyRule(
            id=str(uuid.uuid4()),
            name=data.name,
            description=data.description,
            enabled=data.enabled,
            condition_type=data.condition_type,
            condition_value=data.condition_value,
            action=data.action,
            created_by=creator_id,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        _policy_rules[rule.id] = rule
        return rule

    @staticmethod
    def list_policies() -> List[PolicyRule]:
        return list(_policy_rules.values())

    @staticmethod
    def delete_policy(rule_id: str) -> bool:
        return _policy_rules.pop(rule_id, None) is not None

    @staticmethod
    def user_scan_history(user_id: str, limit: int = 100) -> List[Dict]:
        events = [e for e in _scan_events if e.get("user_id") == user_id]
        return list(reversed(events))[:limit]

    @staticmethod
    def user_risk_score(user_id: str) -> float:
        events = [e for e in _scan_events if e.get("user_id") == user_id]
        if not events:
            return 0.0
        return round(sum(e["final_score"] for e in events) / len(events), 2)
