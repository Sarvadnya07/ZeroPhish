"""
Analytics & Policy service — Repository-backed scan telemetry, heatmaps, threat feed,
model metrics, false-positive review, and policy rule engine.
"""
from __future__ import annotations

import datetime as _dt
import time
import uuid
from typing import Any, Dict, List, Optional

from repositories.factory import get_analytics_repository
from .models import (
    AdminDashboardSummary,
    FalsePositiveReport,
    ModelMetrics,
    PolicyRule,
    PolicyRuleCreate,
    ThreatFeedItem,
    ThreatHeatmapEntry,
)


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
        dt = _dt.datetime.now(_dt.timezone.utc)
        repo = get_analytics_repository()
        repo.record_scan_event({
            "scan_id": scan_id,
            "timestamp": dt.isoformat(),
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

    # ── Dashboard summary ─────────────────────────────────────────────────────

    @staticmethod
    def dashboard_summary() -> AdminDashboardSummary:
        repo = get_analytics_repository()
        summary = repo.get_dashboard_summary()

        try:
            from incidents.service import IncidentService
            inc_stats = IncidentService.stats()
            summary.open_incidents = inc_stats.get("open", 0)
        except Exception:
            pass

        return summary

    # ── Heatmap ───────────────────────────────────────────────────────────────

    @staticmethod
    def threat_heatmap() -> List[ThreatHeatmapEntry]:
        repo = get_analytics_repository()
        return repo.get_threat_heatmap()

    # ── Threat feed ──────────────────────────────────────────────────────────

    @staticmethod
    def threat_feed(limit: int = 50) -> List[ThreatFeedItem]:
        repo = get_analytics_repository()
        return repo.get_threat_feed(limit=limit)

    # ── Model metrics ────────────────────────────────────────────────────────

    @staticmethod
    def model_metrics() -> ModelMetrics:
        repo = get_analytics_repository()
        return repo.get_model_metrics()

    @staticmethod
    def update_model_metrics(fp_delta: int = 0, fn_delta: int = 0) -> None:
        repo = get_analytics_repository()
        repo.update_model_metrics(fp_delta=fp_delta, fn_delta=fn_delta)

    # ── False-positive review ────────────────────────────────────────────────

    @staticmethod
    def report_false_positive(
        scan_id: str,
        reporter_id: str,
        reason: str,
        original_score: float,
        original_verdict: str,
    ) -> FalsePositiveReport:
        repo = get_analytics_repository()
        fp = FalsePositiveReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            reporter_id=reporter_id,
            reason=reason,
            original_score=original_score,
            original_verdict=original_verdict,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        return repo.save_false_positive(fp)

    @staticmethod
    def list_false_positives(reviewed: Optional[bool] = None) -> List[FalsePositiveReport]:
        repo = get_analytics_repository()
        return repo.list_false_positives(reviewed=reviewed)

    @staticmethod
    def review_false_positive(fp_id: str, reviewer_id: str, resolution: str) -> Optional[FalsePositiveReport]:
        repo = get_analytics_repository()
        return repo.review_false_positive(fp_id, reviewer_id, resolution)

    # ── Policy rules ─────────────────────────────────────────────────────────

    @staticmethod
    def create_policy(data: PolicyRuleCreate, creator_id: str) -> PolicyRule:
        repo = get_analytics_repository()
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
        return repo.save_policy_rule(rule)

    @staticmethod
    def list_policies() -> List[PolicyRule]:
        repo = get_analytics_repository()
        return repo.list_policy_rules()

    @staticmethod
    def delete_policy(rule_id: str) -> bool:
        repo = get_analytics_repository()
        return repo.delete_policy_rule(rule_id)

    @staticmethod
    def user_scan_history(user_id: str, limit: int = 100) -> List[Dict]:
        repo = get_analytics_repository()
        events = [e for e in repo.get_scan_events() if e.get("user_id") == user_id]
        return list(reversed(events))[:limit]

    @staticmethod
    def user_risk_score(user_id: str) -> float:
        repo = get_analytics_repository()
        events = [e for e in repo.get_scan_events() if e.get("user_id") == user_id]
        if not events:
            return 0.0
        return round(sum(e.get("final_score", 0.0) for e in events) / len(events), 2)
