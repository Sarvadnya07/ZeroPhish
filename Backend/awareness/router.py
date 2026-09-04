"""
Security Awareness FastAPI router — /awareness/* endpoints.

Provides endpoints for:
- Listing and retrieving lessons (authenticated users)
- Creating lessons (admin only)
- Submitting quiz answers (authenticated)
- Viewing progress (self or analyst for others)
- Leaderboard (authenticated)
- Simulated campaigns (create, list, record clicks/reports)
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Body, status

from auth.middleware import require_admin, require_analyst, require_auth
from auth.models import User

from .models import (
    AwarenessProgress,
    CampaignCreate,
    LeaderboardEntry,
    Lesson,
    LessonCreate,
    QuizSubmit,
    SimulatedCampaign,
)
from .service import AwarenessService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/awareness", tags=["awareness"])


# ---------- Lessons ----------
@router.get(
    "/lessons",
    response_model=List[Lesson],
    summary="List all lessons",
)
def list_lessons(_: User = Depends(require_auth)) -> List[Lesson]:
    """Return all available lessons."""
    return AwarenessService.list_lessons()


@router.get(
    "/lessons/{lesson_id}",
    response_model=Lesson,
    summary="Get a specific lesson by ID",
)
def get_lesson(
    lesson_id: str = Path(..., min_length=1),
    _: User = Depends(require_auth),
) -> Lesson:
    """Return a single lesson's details."""
    lesson = AwarenessService.get_lesson(lesson_id)
    if not lesson:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lesson not found",
        )
    return lesson


@router.post(
    "/lessons",
    status_code=status.HTTP_201_CREATED,
    response_model=Lesson,
    summary="Create a new lesson",
    description="Admin only.",
)
def create_lesson(
    data: LessonCreate,
    _: User = Depends(require_admin),
) -> Lesson:
    """Create a new awareness lesson."""
    return AwarenessService.create_lesson(data)


# ---------- Quiz ----------
@router.post(
    "/lessons/{lesson_id}/quiz",
    response_model=dict,
    summary="Submit a quiz for a lesson",
)
def submit_quiz(
    lesson_id: str = Path(..., min_length=1),
    submission: QuizSubmit = Body(...),
    current_user: User = Depends(require_auth),
) -> dict:
    """Submit quiz answers and receive score, XP earned, and feedback."""
    try:
        return AwarenessService.submit_quiz(lesson_id, current_user.id, submission)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        clean_user_id = str(current_user.id).replace("\n", "").replace("\r", "")
        clean_err = str(e).replace("\n", "").replace("\r", "")
        logger.error("Quiz submission error for user %s: %s", clean_user_id, clean_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process quiz submission",
        )


# ---------- Progress ----------
@router.get(
    "/progress",
    response_model=AwarenessProgress,
    summary="Get current user's progress",
)
def my_progress(current_user: User = Depends(require_auth)) -> AwarenessProgress:
    """Return the authenticated user's progress."""
    return AwarenessService.get_progress(current_user.id)


@router.get(
    "/progress/{user_id}",
    response_model=AwarenessProgress,
    summary="Get progress for a specific user",
    description="Analyst or admin only.",
)
def user_progress(
    user_id: str = Path(..., min_length=1),
    _: User = Depends(require_analyst),
) -> AwarenessProgress:
    """Retrieve progress for a given user (analyst+ only)."""
    return AwarenessService.get_progress(user_id)


# ---------- Leaderboard ----------
@router.get(
    "/leaderboard",
    response_model=List[LeaderboardEntry],
    summary="Global leaderboard",
)
def leaderboard(
    limit: int = Query(20, ge=1, le=100),
    _: User = Depends(require_auth),
) -> List[LeaderboardEntry]:
    """Return the top users by XP and detection score."""
    return AwarenessService.leaderboard(limit=limit)


# ---------- Simulated Campaigns ----------
@router.get(
    "/campaigns",
    response_model=List[SimulatedCampaign],
    summary="List all campaigns",
    description="Analyst+ only.",
)
def list_campaigns(_: User = Depends(require_analyst)) -> List[SimulatedCampaign]:
    """Return all simulated campaigns (analyst+ only)."""
    return AwarenessService.list_campaigns()


@router.post(
    "/campaigns",
    status_code=status.HTTP_201_CREATED,
    response_model=SimulatedCampaign,
    summary="Create a new campaign",
    description="Analyst+ only.",
)
def create_campaign(
    data: CampaignCreate,
    current_user: User = Depends(require_analyst),
) -> SimulatedCampaign:
    """Create a new simulated phishing campaign."""
    return AwarenessService.create_campaign(data, created_by=current_user.id)


@router.post(
    "/campaigns/{campaign_id}/click",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Record a click on a simulated campaign link",
)
def record_click(
    campaign_id: str = Path(..., min_length=1),
    current_user: User = Depends(require_auth),
) -> None:
    """Called when a user clicks a simulated phishing link."""
    AwarenessService.record_click(campaign_id, current_user.id)


@router.post(
    "/campaigns/{campaign_id}/report",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Record a correct report of a simulated campaign",
)
def record_report(
    campaign_id: str = Path(..., min_length=1),
    current_user: User = Depends(require_auth),
) -> None:
    """Called when a user correctly reports a simulated phishing email."""
    AwarenessService.record_report(campaign_id, current_user.id)