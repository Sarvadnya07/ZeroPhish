"""Analytics FastAPI router — /analytics/* and /admin/* endpoints."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException

from auth.middleware import require_auth, require_admin, require_analyst
from auth.models import User

from .models import FalsePositiveReport, PolicyRuleCreate
from .service import AnalyticsService

router = APIRouter(tags=["analytics"])


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/admin/dashboard")
async def admin_dashboard(_: User = Depends(require_analyst)):
    return AnalyticsService.dashboard_summary()


@router.get("/analytics/heatmap")
async def threat_heatmap(_: User = Depends(require_analyst)):
    return AnalyticsService.threat_heatmap()


@router.get("/analytics/threat-feed")
async def threat_feed(limit: int = 50, _: User = Depends(require_analyst)):
    return AnalyticsService.threat_feed(limit=min(limit, 500))


@router.get("/analytics/model-metrics")
async def model_metrics(_: User = Depends(require_analyst)):
    return AnalyticsService.model_metrics()


# ── False-positive review ─────────────────────────────────────────────────────

@router.get("/analytics/false-positives")
async def list_false_positives(
    reviewed: Optional[bool] = None,
    _: User = Depends(require_analyst),
):
    return AnalyticsService.list_false_positives(reviewed=reviewed)


@router.post("/analytics/false-positives", status_code=201)
async def report_false_positive(
    scan_id: str,
    reason: str,
    original_score: float,
    original_verdict: str,
    current_user: User = Depends(require_auth),
):
    return AnalyticsService.report_false_positive(
        scan_id=scan_id,
        reporter_id=current_user.id,
        reason=reason,
        original_score=original_score,
        original_verdict=original_verdict,
    )


@router.patch("/analytics/false-positives/{fp_id}/review")
async def review_false_positive(
    fp_id: str,
    resolution: str,
    current_user: User = Depends(require_analyst),
):
    fp = AnalyticsService.review_false_positive(fp_id, current_user.id, resolution)
    if not fp:
        raise HTTPException(status_code=404, detail="False-positive report not found")
    return fp


# ── Policy management ─────────────────────────────────────────────────────────

@router.get("/admin/policies")
async def list_policies(_: User = Depends(require_admin)):
    return AnalyticsService.list_policies()


@router.post("/admin/policies", status_code=201)
async def create_policy(data: PolicyRuleCreate, current_user: User = Depends(require_admin)):
    return AnalyticsService.create_policy(data, creator_id=current_user.id)


@router.delete("/admin/policies/{rule_id}", status_code=204)
async def delete_policy(rule_id: str, _: User = Depends(require_admin)):
    if not AnalyticsService.delete_policy(rule_id):
        raise HTTPException(status_code=404, detail="Policy rule not found")


# ── Per-user history & risk ───────────────────────────────────────────────────

@router.get("/user/history")
async def my_scan_history(limit: int = 100, current_user: User = Depends(require_auth)):
    return AnalyticsService.user_scan_history(current_user.id, limit=min(limit, 500))


@router.get("/user/risk-score")
async def my_risk_score(current_user: User = Depends(require_auth)):
    return {"risk_score": AnalyticsService.user_risk_score(current_user.id)}
