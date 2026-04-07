"""Security awareness FastAPI router — /awareness/* endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from auth.middleware import require_auth, require_admin, require_analyst
from auth.models import User

from .models import CampaignCreate, LessonCreate, QuizSubmit
from .service import AwarenessService

router = APIRouter(prefix="/awareness", tags=["awareness"])


# ── Lessons ───────────────────────────────────────────────────────────────────

@router.get("/lessons")
async def list_lessons(_: User = Depends(require_auth)):
    return AwarenessService.list_lessons()


@router.get("/lessons/{lesson_id}")
async def get_lesson(lesson_id: str, _: User = Depends(require_auth)):
    lesson = AwarenessService.get_lesson(lesson_id)
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    return lesson


@router.post("/lessons", status_code=201)
async def create_lesson(data: LessonCreate, _: User = Depends(require_admin)):
    return AwarenessService.create_lesson(data)


# ── Quiz ─────────────────────────────────────────────────────────────────────

@router.post("/lessons/{lesson_id}/quiz")
async def submit_quiz(
    lesson_id: str,
    submission: QuizSubmit,
    current_user: User = Depends(require_auth),
):
    try:
        return AwarenessService.submit_quiz(lesson_id, current_user.id, submission)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Progress ──────────────────────────────────────────────────────────────────

@router.get("/progress")
async def my_progress(current_user: User = Depends(require_auth)):
    return AwarenessService.get_progress(current_user.id)


@router.get("/progress/{user_id}")
async def user_progress(user_id: str, _: User = Depends(require_analyst)):
    return AwarenessService.get_progress(user_id)


# ── Leaderboard ───────────────────────────────────────────────────────────────

@router.get("/leaderboard")
async def leaderboard(limit: int = 20, _: User = Depends(require_auth)):
    return AwarenessService.leaderboard(limit=min(limit, 100))


# ── Simulated campaigns ───────────────────────────────────────────────────────

@router.get("/campaigns")
async def list_campaigns(_: User = Depends(require_analyst)):
    return AwarenessService.list_campaigns()


@router.post("/campaigns", status_code=201)
async def create_campaign(data: CampaignCreate, current_user: User = Depends(require_analyst)):
    return AwarenessService.create_campaign(data, created_by=current_user.id)


@router.post("/campaigns/{campaign_id}/click", status_code=204)
async def record_click(campaign_id: str, current_user: User = Depends(require_auth)):
    """Called when user clicks a simulated phishing link."""
    AwarenessService.record_click(campaign_id, current_user.id)


@router.post("/campaigns/{campaign_id}/report", status_code=204)
async def record_report(campaign_id: str, current_user: User = Depends(require_auth)):
    """Called when user correctly reports a simulated phishing email."""
    AwarenessService.record_report(campaign_id, current_user.id)
