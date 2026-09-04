"""
Security awareness service — in-memory store for lessons, campaigns, and user progress.

This service manages the awareness training platform. It currently uses an in-memory
data store (dictionaries) for simplicity, suitable for development and testing.
For production, a persistent repository should be introduced.

The service handles:
- Lesson CRUD
- Quiz evaluation and XP awarding
- User progress tracking (XP, levels, badges)
- Simulated campaign lifecycle (creation, clicks, reports)
- Leaderboard computation

Note: A future refactor should inject a `UserService` dependency to avoid
direct import from `auth.service`.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

# Import the user service for display names; this creates coupling.
# In a more mature design, we would inject a UserRepository or UserService.
from auth.service import AuthService

from .models import (
    AwarenessProgress,
    BadgeName,
    CampaignCreate,
    CampaignStatus,
    LeaderboardEntry,
    Lesson,
    LessonCreate,
    QuizQuestion,
    QuizSubmit,
    SimulatedCampaign,
)

logger = logging.getLogger(__name__)

# In-memory stores
_lessons: Dict[str, Lesson] = {}
_campaigns: Dict[str, SimulatedCampaign] = {}
_progress: Dict[str, AwarenessProgress] = {}  # user_id → progress

# Constants
XP_PER_LEVEL = 500
DETECTION_SCORE_SCALE = 100
BADGE_THRESHOLDS = {
    "first_lesson": 1,       # completed lessons
    "hat_trick": 3,
    "level_2": XP_PER_LEVEL,
    "level_5": XP_PER_LEVEL * 5,
}
CAMPAIGN_REPORT_BONUS_XP = 50
QUIZ_PASS_THRESHOLD = 70  # percentage


def _seed_lessons() -> None:
    """Pre-load starter lessons from a seed file if available."""
    if _lessons:
        return

    try:
        import json
        from pathlib import Path

        seed_file = Path(__file__).parent / "lessons_seed.json"
        if not seed_file.exists():
            logger.info("Seed file not found; starting with empty lessons.")
            return

        with open(seed_file, "r") as f:
            lessons_data = json.load(f)

        for ld in lessons_data:
            lid = str(uuid4())
            # Pop quiz separately, then create Lesson
            quiz_data = ld.pop("quiz", [])
            # Convert quiz list to QuizQuestion objects
            quiz_questions = [QuizQuestion(**q) for q in quiz_data]
            lesson = Lesson(
                id=lid,
                created_at=datetime.now(timezone.utc),
                quiz=quiz_questions,
                **ld,
            )
            _lessons[lid] = lesson
        logger.info("Seeded %d lessons from %s", len(_lessons), seed_file)
    except Exception as e:
        logger.error("Failed to seed lessons: %s", e)


_seed_lessons()


class AwarenessService:
    """Service for security awareness training operations."""

    # ---------- Helpers ----------
    @staticmethod
    def _get_or_create_progress(user_id: str) -> AwarenessProgress:
        """Retrieve or create a new progress record for the user."""
        if user_id not in _progress:
            _progress[user_id] = AwarenessProgress(user_id=user_id)
        return _progress[user_id]

    @staticmethod
    def _update_detection_score(prog: AwarenessProgress) -> None:
        """Recalculate the user's detection score based on campaign interactions."""
        total = len(prog.campaigns_clicked) + len(prog.campaigns_reported)
        if total == 0:
            prog.detection_score = 0.0
            return
        # detection_score = (correct reports) / (total interactions) * 100
        prog.detection_score = round(
            (len(prog.campaigns_reported) / total) * DETECTION_SCORE_SCALE, 1
        )

    @staticmethod
    def _check_badges(prog: AwarenessProgress) -> None:
        """Award badges based on progress."""
        completed = len(prog.lessons_completed)
        xp = prog.xp

        if completed >= 1 and BadgeName.FIRST_LESSON not in prog.badges:
            prog.badges.append(BadgeName.FIRST_LESSON)
        if completed >= 3 and BadgeName.HAT_TRICK not in prog.badges:
            prog.badges.append(BadgeName.HAT_TRICK)
        if xp >= XP_PER_LEVEL and BadgeName.LEVEL_2 not in prog.badges:
            prog.badges.append(BadgeName.LEVEL_2)
        if xp >= XP_PER_LEVEL * 5 and BadgeName.LEVEL_5 not in prog.badges:
            prog.badges.append(BadgeName.LEVEL_5)
        # etc.

    @staticmethod
    def _update_level(prog: AwarenessProgress) -> None:
        """Update level based on XP."""
        prog.level = max(1, (prog.xp // XP_PER_LEVEL) + 1)

    # ---------- Lessons ----------
    @staticmethod
    def list_lessons() -> List[Lesson]:
        """Return all lessons."""
        return list(_lessons.values())

    @staticmethod
    def get_lesson(lesson_id: str) -> Optional[Lesson]:
        """Retrieve a specific lesson by ID."""
        return _lessons.get(lesson_id)

    @staticmethod
    def create_lesson(data: LessonCreate) -> Lesson:
        """Create a new lesson."""
        lid = str(uuid4())
        lesson = Lesson(
            id=lid,
            title=data.title,
            description=data.description,
            difficulty=data.difficulty,
            category=data.category,
            content_md=data.content_md,
            quiz=data.quiz,
            xp_reward=data.xp_reward,
            estimated_minutes=data.estimated_minutes,
            created_at=datetime.now(timezone.utc),
        )
        _lessons[lid] = lesson
        clean_title = str(data.title).replace("\n", "").replace("\r", "")
        clean_lid = str(lid).replace("\n", "").replace("\r", "")
        logger.info("Created lesson: %s (%s)", clean_title, clean_lid)
        return lesson

    # ---------- Quiz ----------
    @staticmethod
    def submit_quiz(lesson_id: str, user_id: str, submission: QuizSubmit) -> dict:
        """Evaluate a quiz submission, award XP, and return results."""
        lesson = _lessons.get(lesson_id)
        if not lesson:
            raise ValueError("Lesson not found")

        # Validate that all question IDs in submission exist in the lesson's quiz
        question_ids = {q.id for q in lesson.quiz}
        for qid in submission.answers.keys():
            if qid not in question_ids:
                raise ValueError(f"Invalid question ID: {qid}")

        correct = 0
        feedback = []
        for q in lesson.quiz:
            selected = submission.answers.get(q.id)
            is_correct = selected == q.correct_index
            if is_correct:
                correct += 1
            feedback.append({
                "question_id": q.id,
                "correct": is_correct,
                "explanation": q.explanation,
            })

        total = len(lesson.quiz)
        score_pct = int((correct / max(total, 1)) * 100)
        passed = score_pct >= QUIZ_PASS_THRESHOLD

        prog = AwarenessService._get_or_create_progress(user_id)
        prog.quiz_scores[lesson_id] = score_pct

        xp_earned = 0
        if passed and lesson_id not in prog.lessons_completed:
            prog.lessons_completed.append(lesson_id)
            xp_earned = lesson.xp_reward
            prog.xp += xp_earned
            AwarenessService._update_level(prog)
            AwarenessService._check_badges(prog)
            clean_user_id = str(user_id).replace("\n", "").replace("\r", "")
            clean_lesson_id = str(lesson_id).replace("\n", "").replace("\r", "")
            logger.info("User %s completed lesson %s, earned %d XP", clean_user_id, clean_lesson_id, xp_earned)

        AwarenessService._update_detection_score(prog)

        return {
            "score_pct": score_pct,
            "correct": correct,
            "total": total,
            "passed": passed,
            "xp_earned": xp_earned,
            "feedback": feedback,
        }

    # ---------- Progress ----------
    @staticmethod
    def get_progress(user_id: str) -> AwarenessProgress:
        """Retrieve or create a progress record for the user."""
        return AwarenessService._get_or_create_progress(user_id)

    # ---------- Simulated Campaigns ----------
    @staticmethod
    def create_campaign(data: CampaignCreate, created_by: str) -> SimulatedCampaign:
        """Create a new simulated phishing campaign."""
        cid = str(uuid4())
        campaign = SimulatedCampaign(
            id=cid,
            name=data.name,
            description=data.description,
            template_subject=data.template_subject,
            template_body=data.template_body,
            target_user_ids=data.target_user_ids,
            total_sent=len(data.target_user_ids),
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
            status=CampaignStatus.DRAFT,
        )
        _campaigns[cid] = campaign
        clean_name = str(data.name).replace("\n", "").replace("\r", "")
        clean_creator = str(created_by or "").replace("\n", "").replace("\r", "")
        logger.info("Created campaign: %s by %s", clean_name, clean_creator)
        return campaign

    @staticmethod
    def list_campaigns() -> List[SimulatedCampaign]:
        """Return all simulated campaigns."""
        return list(_campaigns.values())

    @staticmethod
    def record_click(campaign_id: str, user_id: str) -> None:
        """Record that a user clicked a simulated phishing link."""
        camp = _campaigns.get(campaign_id)
        if camp:
            camp.click_count += 1
        else:
            clean_cid = str(campaign_id).replace("\n", "").replace("\r", "")
            logger.warning("Click recorded for non-existent campaign %s", clean_cid)

        prog = AwarenessService._get_or_create_progress(user_id)
        if campaign_id not in prog.campaigns_clicked:
            prog.campaigns_clicked.append(campaign_id)
        AwarenessService._update_detection_score(prog)

    @staticmethod
    def record_report(campaign_id: str, user_id: str) -> None:
        """Record that a user correctly reported a simulated phishing campaign."""
        camp = _campaigns.get(campaign_id)
        if camp:
            camp.report_count += 1
        else:
            clean_cid = str(campaign_id).replace("\n", "").replace("\r", "")
            logger.warning("Report recorded for non-existent campaign %s", clean_cid)

        prog = AwarenessService._get_or_create_progress(user_id)
        if campaign_id not in prog.campaigns_reported:
            prog.campaigns_reported.append(campaign_id)
            # Bonus XP for correct reporting
            prog.xp += CAMPAIGN_REPORT_BONUS_XP
            AwarenessService._update_level(prog)
            AwarenessService._check_badges(prog)
            clean_user_id = str(user_id).replace("\n", "").replace("\r", "")
            clean_cid = str(campaign_id).replace("\n", "").replace("\r", "")
            logger.info("User %s correctly reported campaign %s, +%d XP",
                        clean_user_id, clean_cid, CAMPAIGN_REPORT_BONUS_XP)

        AwarenessService._update_detection_score(prog)

    # ---------- Leaderboard ----------
    @staticmethod
    def leaderboard(limit: int = 20) -> List[LeaderboardEntry]:
        """Compute and return the top users sorted by XP and detection score."""
        entries = []
        for user_id, prog in _progress.items():
            user = None
            try:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    user = pool.submit(asyncio.run, AuthService.get_user_by_id(user_id)).result()
            except Exception:
                user = None
            display_name = user.full_name if user else user_id[:8]

            entries.append(
                LeaderboardEntry(
                    rank=1,  # will be updated after sorting
                    user_id=user_id,
                    display_name=display_name,
                        title="",
                        description="",
                    xp=prog.xp,
                    lessons_completed=len(prog.lessons_completed),
                    campaigns_reported=len(prog.campaigns_reported),
                    detection_score=prog.detection_score,
                )
            )

        # Sort by XP descending, then detection_score descending
        entries.sort(key=lambda e: (-e.xp, -e.detection_score))
        for i, entry in enumerate(entries[:limit], start=1):
            entry.rank = i

        return entries[:limit]