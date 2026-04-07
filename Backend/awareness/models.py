"""Security Awareness Training — models."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LessonDifficulty(str, Enum):
    BEGINNER     = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED     = "advanced"


class QuizQuestion(BaseModel):
    id: str
    question: str
    options: List[str]
    correct_index: int
    explanation: str


class Lesson(BaseModel):
    id: str
    title: str
    description: str
    difficulty: LessonDifficulty
    category: str           # "phishing" | "spear_phishing" | "smishing" | "bec" | ...
    content_md: str         # Markdown lesson body
    quiz: List[QuizQuestion]
    xp_reward: int = 100
    estimated_minutes: int = 10
    created_at: str


class LessonCreate(BaseModel):
    title: str = Field(..., max_length=200)
    description: str = Field(..., max_length=500)
    difficulty: LessonDifficulty = LessonDifficulty.BEGINNER
    category: str = "phishing"
    content_md: str
    quiz: List[QuizQuestion] = Field(default_factory=list)
    xp_reward: int = 100
    estimated_minutes: int = 10


class CampaignStatus(str, Enum):
    DRAFT    = "draft"
    ACTIVE   = "active"
    COMPLETE = "complete"


class SimulatedCampaign(BaseModel):
    id: str
    name: str
    description: str
    template_subject: str
    template_body: str
    target_user_ids: List[str]
    status: CampaignStatus = CampaignStatus.DRAFT
    click_count: int = 0
    report_count: int = 0
    total_sent: int = 0
    created_by: str
    created_at: str
    completed_at: Optional[str] = None


class CampaignCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: str = ""
    template_subject: str
    template_body: str
    target_user_ids: List[str]


class LeaderboardEntry(BaseModel):
    rank: int
    user_id: str
    display_name: str
    xp: int
    lessons_completed: int
    campaigns_reported: int
    detection_score: float   # % of simulated phishing correctly identified


class AwarenessProgress(BaseModel):
    user_id: str
    xp: int = 0
    level: int = 1
    lessons_completed: List[str] = Field(default_factory=list)
    quiz_scores: Dict[str, int] = Field(default_factory=dict)   # lesson_id → score %
    campaigns_clicked: List[str] = Field(default_factory=list)  # campaign IDs clicked
    campaigns_reported: List[str] = Field(default_factory=list)
    detection_score: float = 0.0
    badges: List[str] = Field(default_factory=list)


class QuizSubmit(BaseModel):
    answers: Dict[str, int]    # question_id → selected_index
