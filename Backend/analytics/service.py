"""
Analytics & Policy service — Repository-backed scan telemetry, heatmaps, threat feed,
model metrics, false-positive review, and policy rule engine.

This service orchestrates all analytics and policy operations, delegating data
persistence to the analytics repository. It handles data transformation,
validation, and provides a clean interface for the API layer.
"""

from __future__ import annotations

import asyncio
import inspect
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

    @staticmethod
    async def record_scan(
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
        Record a completed scan event for analytics and historical reporting (with timeout).
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
            res = repo.record_scan_event(event)
            if inspect.isawaitable(res):
                await asyncio.wait_for(res, timeout=3.0)
        except asyncio.TimeoutError:
            clean_scan_id = str(scan_id).replace("\n", "").replace("\r", "")
            logger.warning("record_scan_event timed out for scan_id=%s", clean_scan_id)
            # Do not re-raise; telemetry should not break the scan flow.
        except Exception as e:
            clean_scan_id = str(scan_id).replace("\n", "").replace("\r", "")
            logger.error("Failed to record scan event for scan_id=%s: %s", clean_scan_id, type(e).__name__)
            # Do not re-raise; telemetry should not break the scan flow.

    @staticmethod
    async def dashboard_summary() -> AdminDashboardSummary:
        """Get high-level dashboard metrics for the current day/week with timeout protection."""
        try:
            repo = get_analytics_repository()
            res = repo.get_dashboard_summary()
            if inspect.isawaitable(res):
                summary = await asyncio.wait_for(res, timeout=10.0)
            else:
                summary = res

            # Inject open incidents count from the incidents service
            try:
                from incidents.service import IncidentService

                raw_stats = IncidentService.stats()
                if inspect.isawaitable(raw_stats):
                    inc_stats = await asyncio.wait_for(raw_stats, timeout=5.0)
                else:
                    inc_stats = raw_stats
                summary.open_incidents = inc_stats.get("open", 0)
            except asyncio.TimeoutError:
                logger.warning("IncidentService timed out; open_incidents remains default")
            except ImportError:
                logger.warning("IncidentService not available; open_incidents remains default")
            except Exception as e:
                logger.error("Failed to fetch incident stats: %s", e)

            return summary
        except asyncio.TimeoutError:
            logger.error("dashboard_summary operation timed out")
            # Return a safe default
            from .models import AdminDashboardSummary
            return AdminDashboardSummary(
                total_scans_today=0,
                total_scans_week=0,
                critical_today=0,
                suspicious_today=0,
                safe_today=0,
                avg_score_today=0.0,
                false_positives_pending=0,
                open_incidents=0,
                circuit_breaker_state="unknown",
                top_malicious_domains=[],
                top_senders=[],
                model_accuracy=0.0,
            )
        except Exception as e:
            logger.error("Error in dashboard_summary: %s", e)
            from .models import AdminDashboardSummary
            return AdminDashboardSummary(
                total_scans_today=0,
                total_scans_week=0,
                critical_today=0,
                suspicious_today=0,
                safe_today=0,
                avg_score_today=0.0,
                false_positives_pending=0,
                open_incidents=0,
                circuit_breaker_state="unknown",
                top_malicious_domains=[],
                top_senders=[],
                model_accuracy=0.0,
            )

    # ---------- Heatmap ----------
    @staticmethod
    async def threat_heatmap() -> list[ThreatHeatmapEntry]:
        """Get aggregated threat data by hour/day for the past week with timeout."""
        try:
            repo = get_analytics_repository()
            res = repo.get_threat_heatmap()
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=10.0)
            return res
        except asyncio.TimeoutError:
            logger.error("threat_heatmap operation timed out")
            # Return default empty heatmap
            result = []
            for d in range(7):
                for h in range(24):
                    result.append(ThreatHeatmapEntry(day=d, hour=h, count=0, avg_score=0.0))
            return result
        except Exception as e:
            logger.error("Error in threat_heatmap: %s", e)
            result = []
            for d in range(7):
                for h in range(24):
                    result.append(ThreatHeatmapEntry(day=d, hour=h, count=0, avg_score=0.0))
            return result

    # ---------- Threat Feed ----------
    @staticmethod
    async def threat_feed(limit: int = 50) -> list[ThreatFeedItem]:
        """
        Get the latest threat feed items, most recent first (with timeout).
        """
        if limit < 1:
            limit = 50
        if limit > AnalyticsService.MAX_FEED_LIMIT:
            limit = AnalyticsService.MAX_FEED_LIMIT

        try:
            repo = get_analytics_repository()
            res = repo.get_threat_feed(limit=limit)
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=10.0)
            return res
        except asyncio.TimeoutError:
            logger.error("threat_feed operation timed out")
            return []
        except Exception as e:
            logger.error("Error in threat_feed: %s", e)
            return []

    # ---------- Model Metrics ----------
    @staticmethod
    async def model_metrics() -> ModelMetrics:
        """Get the latest ML model performance metrics with timeout."""
        try:
            repo = get_analytics_repository()
            res = repo.get_model_metrics()
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            logger.error("model_metrics operation timed out")
            return ModelMetrics(
                model_id="unknown",
                accuracy=0.0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                total_inferences=0,
                avg_latency_ms=0.0,
                false_positive_rate=0.0,
                false_negative_rate=0.0,
                last_evaluated=datetime.now(timezone.utc),
            )
        except Exception as e:
            logger.error("Error in model_metrics: %s", e)
            return ModelMetrics(
                model_id="unknown",
                accuracy=0.0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                total_inferences=0,
                avg_latency_ms=0.0,
                false_positive_rate=0.0,
                false_negative_rate=0.0,
                last_evaluated=datetime.now(timezone.utc),
            )

    @staticmethod
    async def update_model_metrics(fp_delta: int = 0, fn_delta: int = 0) -> None:
        """Increment the model's false-positive and false-negative counts with timeout."""
        try:
            repo = get_analytics_repository()
            res = repo.update_model_metrics(fp_delta=fp_delta, fn_delta=fn_delta)
            if inspect.isawaitable(res):
                await asyncio.wait_for(res, timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("update_model_metrics timed out")
        except Exception as e:
            logger.error("Error updating model metrics: %s", e)

    @staticmethod
    async def report_false_positive(
        scan_id: str,
        reporter_id: str,
        reason: str,
        original_score: float,
        original_verdict: str,
    ) -> FalsePositiveReport:
        """
        Submit a false-positive report for a previous scan with timeout.
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

        try:
            repo = get_analytics_repository()
            res = repo.save_false_positive(fp)
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            clean_scan_id = str(scan_id).replace("\n", "").replace("\r", "")
            logger.error("report_false_positive timed out for scan_id=%s", clean_scan_id)
            return fp  # Return the report even if save times out
        except Exception as e:
            logger.error("Error saving false positive: %s", type(e).__name__)
            return fp  # Return the report even if save fails

    @staticmethod
    async def list_false_positives(reviewed: Optional[bool] = None) -> list[FalsePositiveReport]:
        """List false-positive reports with timeout."""
        try:
            repo = get_analytics_repository()
            res = repo.list_false_positives(reviewed=reviewed)
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            logger.warning("list_false_positives timed out")
            return []
        except Exception as e:
            logger.error("Error listing false positives: %s", type(e).__name__)
            return []

    @staticmethod
    async def review_false_positive(
        fp_id: str, reviewer_id: str, resolution: str
    ) -> Optional[FalsePositiveReport]:
        """
        Mark a false-positive report as reviewed with timeout.
        """
        if not fp_id or not reviewer_id or not resolution:
            raise ValueError("fp_id, reviewer_id, and resolution are required")

        try:
            repo = get_analytics_repository()
            res = repo.review_false_positive(fp_id, reviewer_id, resolution)
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            clean_fp_id = str(fp_id).replace("\n", "").replace("\r", "")
            logger.error("review_false_positive timed out for fp_id=%s", clean_fp_id)
            return None
        except Exception as e:
            logger.error("Error reviewing false positive: %s", type(e).__name__)
            return None

    # ---------- Policy Rules ----------
    @staticmethod
    async def create_policy(data: PolicyRuleCreate, creator_id: str) -> PolicyRule:
        """
        Create a new policy rule with timeout.
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

        try:
            repo = get_analytics_repository()
            res = repo.save_policy_rule(rule)
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            logger.warning("create_policy timed out")
            return rule  # Return the rule even if save times out
        except Exception as e:
            logger.error("Error creating policy: %s", e)
            return rule  # Return the rule even if save fails

    @staticmethod
    async def list_policies() -> list[PolicyRule]:
        """List all policy rules with timeout."""
        try:
            repo = get_analytics_repository()
            res = repo.list_policy_rules()
            if inspect.isawaitable(res):
                return await asyncio.wait_for(res, timeout=5.0)
            return res
        except asyncio.TimeoutError:
            logger.warning("list_policies timed out")
            return []
        except Exception as e:
            logger.error("Error listing policies: %s", e)
            return []

    @staticmethod
    async def delete_policy(rule_id: str) -> bool:
        """Delete a policy rule by ID with timeout."""
        if not rule_id:
            return False
        try:
            repo = get_analytics_repository()
            res = repo.delete_policy_rule(rule_id)
            if inspect.isawaitable(res):
                result = await asyncio.wait_for(res, timeout=5.0)
            else:
                result = res
            return result if isinstance(result, bool) else False
        except asyncio.TimeoutError:
            clean_rule_id = str(rule_id).replace("\n", "").replace("\r", "")
            logger.warning("delete_policy timed out for rule_id=%s", clean_rule_id)
            return False
        except Exception as e:
            logger.error("Error deleting policy: %s", type(e).__name__)
            return False

    # ---------- User-Specific Queries ----------
    @staticmethod
    async def user_scan_history(user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get the scan history for a specific user (optimized with early filtering).
        """
        if not user_id:
            return []

        if limit < 1:
            limit = 100
        if limit > AnalyticsService.MAX_FEED_LIMIT:
            limit = AnalyticsService.MAX_FEED_LIMIT

        try:
            repo = get_analytics_repository()
            res = repo.get_scan_events(limit=limit * 5)  # Request only what we might need
            if inspect.isawaitable(res):
                all_events = await asyncio.wait_for(res, timeout=5.0)
            else:
                all_events = res
            
            # Filter and sort with early exit
            user_events = []
            for event in reversed(all_events):  # Iterate in reverse for most recent first
                if event.get("user_id") == user_id:
                    user_events.append(event)
                    if len(user_events) >= limit:
                        break
            return user_events
        except asyncio.TimeoutError:
            clean_uid = str(user_id).replace("\n", "").replace("\r", "")
            logger.warning("user_scan_history timed out for user_id=%s", clean_uid)
            return []
        except Exception as e:
            logger.error("Error fetching user_scan_history: %s", type(e).__name__)
            return []

    @staticmethod
    async def user_risk_score(user_id: str) -> float:
        """
        Calculate the average threat score for a user's scan history (optimized).
        """
        if not user_id:
            return AnalyticsService.DEFAULT_RISK_SCORE

        try:
            repo = get_analytics_repository()
            res = repo.get_scan_events(limit=1000)  # Limit to prevent loading entire dataset
            if inspect.isawaitable(res):
                all_events = await asyncio.wait_for(res, timeout=5.0)
            else:
                all_events = res
            
            # Calculate average in single pass
            total_score = 0.0
            count = 0
            for e in all_events:
                if e.get("user_id") == user_id:
                    total_score += e.get("final_score", 0.0)
                    count += 1

            if count == 0:
                return AnalyticsService.DEFAULT_RISK_SCORE
            
            avg_score = total_score / count
            return round(avg_score, 2)
        except asyncio.TimeoutError:
            clean_uid = str(user_id).replace("\n", "").replace("\r", "")
            logger.warning("user_risk_score timed out for user_id=%s", clean_uid)
            return AnalyticsService.DEFAULT_RISK_SCORE
        except Exception as e:
            logger.error("Error calculating user_risk_score: %s", type(e).__name__)
            return AnalyticsService.DEFAULT_RISK_SCORE