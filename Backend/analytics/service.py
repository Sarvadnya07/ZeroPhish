"""
Analytics & Policy service — Repository-backed scan telemetry, heatmaps, threat feed,
model metrics, false-positive review, and policy rule engine.

This service orchestrates all analytics and policy operations, delegating data
persistence to the analytics repository. It handles data transformation,
validation, and provides a clean interface for the API layer.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from repositories.factory import get_analytics_repository

# Import enhanced models (enums and schemas)
from .models import (
    AdminDashboardSummary,
    FalsePositiveReport,
    ModelMetrics,
    PolicyRule,
    PolicyRuleCreate,
    ThreatFeedItem,
    ThreatHeatmapEntry,
    Verdict,
)

logger = logging.getLogger(__name__)


class AnalyticsService:
    """
    Service layer for analytics, telemetry, and policy management.

    All methods are static for simplicity; they retrieve the repository
    instance on each call. In a future refactor, dependency injection
    could be introduced for better testability.
    """

    # ---------- Constants ----------
    MAX_SUBJECT_SNIPPET_LENGTH = 80
    MAX_FEED_LIMIT = 500
    DEFAULT_RISK_SCORE = 0.0
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # ---------- Telemetry Ingestion ----------
    @staticmethod
    def record_scan(
        scan_id: str,
        sender: str,
        subject: str,
        final_score: float,
        verdict: str,
        category: str,
        tier1: float = 0.0,
        tier2: float = 0.0,
        tier3: float = 0.0,
        user_id: Optional[str] = None,
    ) -> None:
        """
        Record a completed scan event for analytics and historical reporting.

        Args:
            scan_id: Unique identifier for the scan.
            sender: Sender email address.
            subject: Email subject line.
            final_score: Aggregated threat score (0-100).
            verdict: Final verdict string (SAFE, SUSPICIOUS, CRITICAL).
            category: Threat category (e.g., BEC, Credential, Safe).
            tier1: Tier 1 heuristic score.
            tier2: Tier 2 ML/OSINT score.
            tier3: Tier 3 Gemini semantic score.
            user_id: Optional user identifier for per-user tracking.

        Raises:
            ValueError: If input validation fails (e.g., score out of range).
        """
        # Validate inputs
        if not scan_id or not sender:
            raise ValueError("scan_id and sender are required")
        if not (0.0 <= final_score <= 100.0):
            raise ValueError(f"final_score must be between 0 and 100, got {final_score}")

        now = datetime.now(timezone.utc)
        domain = sender.split("@")[-1] if "@" in sender else sender

        event = {
            "scan_id": scan_id,
            "timestamp": now.isoformat(),
            "ts": now.timestamp(),
            "hour": now.hour,
            "day": now.weekday(),
            "sender_domain": domain,
            "subject": subject[: AnalyticsService.MAX_SUBJECT_SNIPPET_LENGTH],
            "final_score": final_score,
            "verdict": verdict,
            "category": category,
            "tier1_score": tier1,
            "tier2_score": tier2,
            "tier3_score": tier3,
            "user_id": user_id,  # May be None
        }

        repo = get_analytics_repository()
        try:
            repo.record_scan_event(event)
        except Exception as e:
            logger.error("Failed to record scan event for scan_id=%s: %s", scan_id, e)
            # Do not re-raise; telemetry should not break the scan flow.

    # ---------- Dashboard Summary ----------
    @staticmethod
    def dashboard_summary() -> AdminDashboardSummary:
        """Get high-level dashboard metrics for the current day/week."""
        repo = get_analytics_repository()
        summary = repo.get_dashboard_summary()

        # Inject open incidents count from the incidents service
        try:
            from incidents.service import IncidentService

            inc_stats = IncidentService.stats()
            summary.open_incidents = inc_stats.get("open", 0)
        except ImportError:
            logger.warning("IncidentService not available; open_incidents remains default")
        except Exception as e:
            logger.error("Failed to fetch incident stats: %s", e)

        return summary

    # ---------- Heatmap ----------
    @staticmethod
    def threat_heatmap() -> list[ThreatHeatmapEntry]:
        """Get aggregated threat data by hour/day for the past week."""
        repo = get_analytics_repository()
        return repo.get_threat_heatmap()

    # ---------- Threat Feed ----------
    @staticmethod
    def threat_feed(limit: int = 50) -> list[ThreatFeedItem]:
        """
        Get the latest threat feed items, most recent first.

        Args:
            limit: Maximum number of items to return (capped at MAX_FEED_LIMIT).

        Returns:
            List of ThreatFeedItem objects sorted by timestamp descending.
        """
        if limit < 1:
            limit = 50
        if limit > AnalyticsService.MAX_FEED_LIMIT:
            limit = AnalyticsService.MAX_FEED_LIMIT

        repo = get_analytics_repository()
        return repo.get_threat_feed(limit=limit)

    # ---------- Model Metrics ----------
    @staticmethod
    def model_metrics() -> ModelMetrics:
        """Get the latest ML model performance metrics."""
        repo = get_analytics_repository()
        return repo.get_model_metrics()

    @staticmethod
    def update_model_metrics(fp_delta: int = 0, fn_delta: int = 0) -> None:
        """
        Increment the model's false-positive and false-negative counts.

        Args:
            fp_delta: Number of new false positives (can be negative).
            fn_delta: Number of new false negatives (can be negative).
        """
        repo = get_analytics_repository()
        repo.update_model_metrics(fp_delta=fp_delta, fn_delta=fn_delta)

    # ---------- False-Positive Review ----------
    @staticmethod
    def report_false_positive(
        scan_id: str,
        reporter_id: str,
        reason: str,
        original_score: float,
        original_verdict: str,
    ) -> FalsePositiveReport:
        """
        Submit a false-positive report for a previous scan.

        Args:
            scan_id: ID of the scan being reported.
            reporter_id: User ID of the reporter.
            reason: Explanation of why it's a false positive.
            original_score: The original threat score.
            original_verdict: The original verdict string.

        Returns:
            The created FalsePositiveReport object.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        if not scan_id or not reporter_id or not reason:
            raise ValueError("scan_id, reporter_id, and reason are required")
        if not (0.0 <= original_score <= 100.0):
            raise ValueError("original_score must be between 0 and 100")

        # Validate verdict is a known enum value
        try:
            verdict_enum = Verdict(original_verdict)
        except ValueError:
            raise ValueError(f"Invalid original_verdict: {original_verdict}")

        now = datetime.now(timezone.utc)
        fp = FalsePositiveReport(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            reporter_id=reporter_id,
            reason=reason,
            original_score=original_score,
            original_verdict=verdict_enum,
            created_at=now,
            reviewed=False,
        )

        repo = get_analytics_repository()
        return repo.save_false_positive(fp)

    @staticmethod
    def list_false_positives(reviewed: Optional[bool] = None) -> list[FalsePositiveReport]:
        """List false-positive reports, optionally filtering by review status."""
        repo = get_analytics_repository()
        return repo.list_false_positives(reviewed=reviewed)

    @staticmethod
    def review_false_positive(
        fp_id: str, reviewer_id: str, resolution: str
    ) -> Optional[FalsePositiveReport]:
        """
        Mark a false-positive report as reviewed.

        Args:
            fp_id: False-positive report ID.
            reviewer_id: User ID of the reviewer.
            resolution: Resolution comment.

        Returns:
            Updated FalsePositiveReport, or None if not found.
        """
        if not fp_id or not reviewer_id or not resolution:
            raise ValueError("fp_id, reviewer_id, and resolution are required")

        repo = get_analytics_repository()
        return repo.review_false_positive(fp_id, reviewer_id, resolution)

    # ---------- Policy Rules ----------
    @staticmethod
    def create_policy(data: PolicyRuleCreate, creator_id: str) -> PolicyRule:
        """
        Create a new policy rule.

        Args:
            data: PolicyRuleCreate payload.
            creator_id: User ID of the creator.

        Returns:
            The created PolicyRule object.
        """
        if not data.name or not data.condition_value:
            raise ValueError("name and condition_value are required")

        now = datetime.now(timezone.utc)
        rule = PolicyRule(
            id=str(uuid.uuid4()),
            name=data.name,
            description=data.description or "",
            enabled=data.enabled,
            condition_type=data.condition_type,
            condition_value=data.condition_value,
            action=data.action,
            created_by=creator_id,
            created_at=now,
        )

        repo = get_analytics_repository()
        return repo.save_policy_rule(rule)

    @staticmethod
    def list_policies() -> list[PolicyRule]:
        """List all policy rules."""
        repo = get_analytics_repository()
        return repo.list_policy_rules()

    @staticmethod
    def delete_policy(rule_id: str) -> bool:
        """Delete a policy rule by ID. Returns True if deleted, False otherwise."""
        if not rule_id:
            return False
        repo = get_analytics_repository()
        return repo.delete_policy_rule(rule_id)

    # ---------- User-Specific Queries ----------
    @staticmethod
    def user_scan_history(user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get the scan history for a specific user.

        NOTE: This implementation currently fetches all events and filters in-memory.
        For production scalability, the repository should support a 'user_id' filter
        at the data store level. This is a temporary workaround.

        Args:
            user_id: User identifier.
            limit: Maximum number of events to return.

        Returns:
            List of scan events (dicts), most recent first.
        """
        if not user_id:
            return []

        if limit < 1:
            limit = 100
        if limit > AnalyticsService.MAX_FEED_LIMIT:
            limit = AnalyticsService.MAX_FEED_LIMIT

        repo = get_analytics_repository()
        all_events = repo.get_scan_events()
        user_events = [
            event for event in all_events
            if event.get("user_id") == user_id
        ]
        # Sort by timestamp descending (most recent first)
        user_events.sort(key=lambda e: e.get("ts", 0), reverse=True)
        return user_events[:limit]

    @staticmethod
    def user_risk_score(user_id: str) -> float:
        """
        Calculate the average threat score for a user's scan history.

        Returns:
            Float between 0 and 100, or 0.0 if no scans exist.
        """
        if not user_id:
            return AnalyticsService.DEFAULT_RISK_SCORE

        repo = get_analytics_repository()
        all_events = repo.get_scan_events()
        user_scores = [
            e.get("final_score", 0.0)
            for e in all_events
            if e.get("user_id") == user_id
        ]

        if not user_scores:
            return AnalyticsService.DEFAULT_RISK_SCORE

        avg_score = sum(user_scores) / len(user_scores)
        return round(avg_score, 2)