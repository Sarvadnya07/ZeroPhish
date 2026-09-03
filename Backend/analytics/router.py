"""
Analytics FastAPI router — /analytics/* and /admin/* endpoints.

This router provides endpoints for:
- Admin dashboards and threat heatmaps
- Real-time threat feed
- Model performance metrics
- False-positive reporting and review
- Security policy management (admin only)
- Per-user scan history and risk scores

All endpoints are protected by role-based access control (RBAC) and
use Pydantic models for request/response validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from auth.middleware import require_admin, require_analyst, require_auth
from auth.models import User

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
from .service import AnalyticsService

router = APIRouter(tags=["analytics"])


# ---------- Dependency injection aliases ----------
CurrentUser = Annotated[User, Depends(require_auth)]
AnalystUser = Annotated[User, Depends(require_analyst)]
AdminUser = Annotated[User, Depends(require_admin)]


# ---------- Dashboard & Analytics ----------
@router.get(
    "/admin/dashboard",
    response_model=AdminDashboardSummary,
    summary="Admin dashboard summary",
    description="Returns high-level metrics for the current day and week.",
)
async def admin_dashboard(_: AnalystUser) -> AdminDashboardSummary:
    """Get the admin dashboard summary."""
    return await AnalyticsService.dashboard_summary()


@router.get(
    "/analytics/heatmap",
    response_model=list[ThreatHeatmapEntry],
    summary="Threat heatmap by hour/day",
)
async def threat_heatmap(_: AnalystUser) -> list[ThreatHeatmapEntry]:
    """Get aggregated threat data for the past week, grouped by hour and day."""
    return await AnalyticsService.threat_heatmap()


@router.get(
    "/analytics/threat-feed",
    response_model=list[ThreatFeedItem],
    summary="Real-time threat feed",
    description="Returns recent threat items sorted by timestamp descending.",
)
async def threat_feed(
    _: AnalystUser,
    limit: Annotated[int, Query(ge=1, le=500, description="Max number of items")] = 50,
) -> list[ThreatFeedItem]:
    """Get the latest threat feed items."""
    return await AnalyticsService.threat_feed(limit=limit)


@router.get(
    "/analytics/model-metrics",
    response_model=ModelMetrics,
    summary="Current ML model performance metrics",
)
async def model_metrics(_: AnalystUser) -> ModelMetrics:
    """Get the latest performance metrics for the DistilBERT model."""
    return await AnalyticsService.model_metrics()


# ---------- False-Positive Reporting ----------
@router.get(
    "/analytics/false-positives",
    response_model=list[FalsePositiveReport],
    summary="List false-positive reports",
)
async def list_false_positives(
    _: AnalystUser,
    reviewed: Annotated[
        Optional[bool],
        Query(description="Filter by reviewed status (true/false)"),
    ] = None,
) -> list[FalsePositiveReport]:
    """List all false-positive reports, optionally filtering by review status."""
    return await AnalyticsService.list_false_positives(reviewed=reviewed)


@router.post(
    "/analytics/false-positives",
    status_code=status.HTTP_201_CREATED,
    response_model=FalsePositiveReport,
    summary="Submit a false-positive report",
)
async def report_false_positive(
    current_user: CurrentUser,
    scan_id: Annotated[str, Query(min_length=1, description="ID of the scan")],
    reason: Annotated[str, Query(min_length=1, description="Why this is a false positive")],
    original_score: Annotated[float, Query(ge=0.0, le=100.0)],
    original_verdict: Annotated[Verdict, Query(description="Original verdict of the scan")],
) -> FalsePositiveReport:
    """Report a false positive for a previous scan."""
    return await AnalyticsService.report_false_positive(
        scan_id=scan_id,
        reporter_id=current_user.id,
        reason=reason,
        original_score=original_score,
        original_verdict=original_verdict.value,
    )


@router.patch(
    "/analytics/false-positives/{fp_id}/review",
    response_model=FalsePositiveReport,
    summary="Review a false-positive report",
)
async def review_false_positive(
    fp_id: Annotated[str, Path(description="False-positive report ID")],
    resolution: Annotated[str, Query(min_length=1, description="Resolution comment")],
    current_user: AnalystUser,
) -> FalsePositiveReport:
    """Mark a false-positive report as reviewed, adding a resolution."""
    fp = await AnalyticsService.review_false_positive(
        fp_id,
        reviewer_id=current_user.id,
        resolution=resolution,
    )
    if fp is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="False-positive report not found",
        )
    return fp


# ---------- Policy Management (Admin only) ----------
@router.get(
    "/admin/policies",
    response_model=list[PolicyRule],
    summary="List all security policies",
)
async def list_policies(_: AdminUser) -> list[PolicyRule]:
    """Get all policy rules (admin only)."""
    return await AnalyticsService.list_policies()


@router.post(
    "/admin/policies",
    status_code=status.HTTP_201_CREATED,
    response_model=PolicyRule,
    summary="Create a new policy rule",
)
async def create_policy(
    data: PolicyRuleCreate,
    current_user: AdminUser,
) -> PolicyRule:
    """Create a new security policy rule (admin only)."""
    return await AnalyticsService.create_policy(data, creator_id=current_user.id)


@router.delete(
    "/admin/policies/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a policy rule",
)
async def delete_policy(
    rule_id: Annotated[str, Path(description="Policy rule ID")],
    _: AdminUser,
) -> None:
    """Delete a security policy rule (admin only)."""
    deleted = await AnalyticsService.delete_policy(rule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy rule not found",
        )


# ---------- User-Specific Endpoints ----------
@router.get(
    "/user/history",
    response_model=list[dict],
    summary="User's scan history",
)
async def my_scan_history(
    current_user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500, description="Number of scans to return")] = 100,
) -> list[dict]:
    """Get the current user's scan history, most recent first."""
    return await AnalyticsService.user_scan_history(current_user.id, limit=limit)


@router.get(
    "/user/risk-score",
    response_model=dict[str, float],
    summary="User's personal risk score",
)
async def my_risk_score(current_user: CurrentUser) -> dict[str, float]:
    """Get the current user's aggregated risk score based on their scan history."""
    return {"risk_score": await AnalyticsService.user_risk_score(current_user.id)}