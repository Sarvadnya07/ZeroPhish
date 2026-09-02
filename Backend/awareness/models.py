"""Security Awareness Training — models.

This module defines the data contracts for the security awareness platform,
including lessons, quizzes, simulated phishing campaigns, user progress,
and leaderboard entries.

All models include validation and field constraints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------- Enums ----------
class LessonDifficulty(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class LessonCategory(str, Enum):
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    SMISHING = "smishing"
    BEC = "bec"
    VISHING = "vishing"
    SOCIAL_ENGINEERING = "social_engineering"
    GENERAL = "general"


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETE = "complete"


class BadgeName(str, Enum):
    FIRST_LESSON = "first_lesson"
    HAT_TRICK = "hat_trick"
    LEVEL_2 = "level_2"
    LEVEL_5 = "level_5"
    PHISHING_EXPERT = "phishing_expert"
    DETECTIVE = "detective"


# ---------- Lesson & Quiz Models ----------
class QuizQuestion(BaseModel):
    """A single multiple-choice question within a lesson quiz."""

    id: str = Field(..., min_length=1, description="Unique question ID")
    question: str = Field(..., min_length=1, max_length=500)
    options: List[str] = Field(..., min_length=2, max_length=6, description="Possible answers")
    correct_index: int = Field(..., ge=0, description="Index of the correct answer in `options`")
    explanation: str = Field(..., min_length=1, max_length=1000)

    @field_validator("correct_index")
    @classmethod
    def validate_index(cls, v: int) -> int:
        return v


class Lesson(BaseModel):
    """A complete lesson with content, quiz, and XP reward."""

    id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., max_length=500)
    difficulty: LessonDifficulty = LessonDifficulty.BEGINNER
    category: LessonCategory = LessonCategory.GENERAL
    content_md: str = Field(..., description="Lesson content in Markdown format")
    quiz: List[QuizQuestion] = Field(default_factory=list)
    xp_reward: int = Field(default=100, ge=10, le=1000)
    estimated_minutes: int = Field(default=10, ge=1, le=120)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LessonCreate(BaseModel):
    """Payload for creating a new lesson."""

    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., max_length=500)
    difficulty: LessonDifficulty = LessonDifficulty.BEGINNER
    category: LessonCategory = LessonCategory.GENERAL
    content_md: str = Field(..., min_length=1)
    quiz: List[QuizQuestion] = Field(default_factory=list)
    xp_reward: int = Field(default=100, ge=10, le=1000)
    estimated_minutes: int = Field(default=10, ge=1, le=120)


# ---------- Campaign Models ----------
class SimulatedCampaign(BaseModel):
    """A simulated phishing campaign for user training."""

    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    template_subject: str = Field(..., min_length=1)
    template_body: str = Field(..., min_length=1)
    target_user_ids: List[str] = Field(default_factory=list)
    status: CampaignStatus = CampaignStatus.DRAFT
    click_count: int = Field(default=0, ge=0)
    report_count: int = Field(default=0, ge=0)
    total_sent: int = Field(default=0, ge=0)
    created_by: str = Field(..., min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class CampaignCreate(BaseModel):
    """Payload for creating a new campaign."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    template_subject: str = Field(..., min_length=1)
    template_body: str = Field(..., min_length=1)
    target_user_ids: List[str] = Field(..., min_length=1)


# ---------- Progress & Leaderboard ----------
class AwarenessProgress(BaseModel):
    """User's progress through the awareness training."""

    user_id: str = Field(..., min_length=1)
    xp: int = Field(default=0, ge=0)
    level: int = Field(default=1, ge=1)
    lessons_completed: List[str] = Field(default_factory=list)
    quiz_scores: Dict[str, int] = Field(default_factory=dict)  # lesson_id → score % (0-100)
    campaigns_clicked: List[str] = Field(default_factory=list)  # campaign IDs where user clicked
    campaigns_reported: List[str] = Field(default_factory=list)  # campaign IDs correctly reported
    detection_score: float = Field(default=0.0, ge=0.0, le=100.0)  # % of campaigns correctly handled
    badges: List[BadgeName] = Field(default_factory=list)


class QuizSubmit(BaseModel):
    """Payload for submitting a quiz."""

    answers: Dict[str, int] = Field(
        ...,
        description="Mapping of question_id → selected answer index",
    )


class LeaderboardEntry(BaseModel):
    """A user's entry in the leaderboard."""

    rank: int = Field(..., ge=1)
    user_id: str = Field(..., min_length=1)
    display_name: str = Field(..., min_length=1)
    xp: int = Field(..., ge=0)
    lessons_completed: int = Field(..., ge=0)
    campaigns_reported: int = Field(..., ge=0)
    detection_score: float = Field(..., ge=0.0, le=100.0)
    title: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
