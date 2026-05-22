"""Security awareness service."""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional

from .models import (
    AwarenessProgress,
    CampaignCreate,
    LeaderboardEntry,
    Lesson,
    LessonCreate,
    QuizSubmit,
    SimulatedCampaign,
)

_lessons: Dict[str, Lesson] = {}
_campaigns: Dict[str, SimulatedCampaign] = {}
_progress: Dict[str, AwarenessProgress] = {}  # user_id → progress


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _get_or_create_progress(user_id: str) -> AwarenessProgress:
    if user_id not in _progress:
        _progress[user_id] = AwarenessProgress(user_id=user_id)
    return _progress[user_id]


def _seed_lessons() -> None:
    """Pre-load 3 starter lessons if empty."""
    if _lessons:
        return

    import json
    from pathlib import Path

    seed_file = Path(__file__).parent / "lessons_seed.json"
    if not seed_file.exists():
        return

    with open(seed_file, "r") as f:
        lessons_data = json.load(f)

    for ld in lessons_data:
        lid = str(uuid.uuid4())
        quiz = ld.pop("quiz")
        _lessons[lid] = Lesson(
            id=lid,
            created_at=_now(),
            quiz=quiz,
            **ld,  # type: ignore[arg-type]
        )


_seed_lessons()


class AwarenessService:

    # ── Lessons ───────────────────────────────────────────────────────────────

    @staticmethod
    def list_lessons() -> List[Lesson]:
        return list(_lessons.values())

    @staticmethod
    def get_lesson(lesson_id: str) -> Optional[Lesson]:
        return _lessons.get(lesson_id)

    @staticmethod
    def create_lesson(data: LessonCreate) -> Lesson:
        lid = str(uuid.uuid4())
        lesson = Lesson(id=lid, created_at=_now(), **data.model_dump())
        _lessons[lid] = lesson
        return lesson

    # ── Quiz ─────────────────────────────────────────────────────────────────

    @staticmethod
    def submit_quiz(lesson_id: str, user_id: str, submission: QuizSubmit) -> dict:
        lesson = _lessons.get(lesson_id)
        if not lesson:
            raise ValueError("Lesson not found")

        correct = 0
        feedback = []
        for q in lesson.quiz:
            selected = submission.answers.get(q.id)
            is_correct = selected == q.correct_index
            if is_correct:
                correct += 1
            feedback.append(
                {
                    "question_id": q.id,
                    "correct": is_correct,
                    "explanation": q.explanation,
                }
            )

        score_pct = int((correct / max(len(lesson.quiz), 1)) * 100)
        passed = score_pct >= 70

        prog = _get_or_create_progress(user_id)
        prog.quiz_scores[lesson_id] = score_pct
        if passed and lesson_id not in prog.lessons_completed:
            prog.lessons_completed.append(lesson_id)
            prog.xp += lesson.xp_reward
            prog.level = max(1, prog.xp // 500 + 1)
            AwarenessService._check_badges(prog)

        AwarenessService._update_detection_score(prog)

        return {
            "score_pct": score_pct,
            "correct": correct,
            "total": len(lesson.quiz),
            "passed": passed,
            "xp_earned": lesson.xp_reward if passed else 0,
            "feedback": feedback,
        }

    @staticmethod
    def _check_badges(prog: AwarenessProgress) -> None:
        if len(prog.lessons_completed) >= 1 and "first_lesson" not in prog.badges:
            prog.badges.append("first_lesson")
        if len(prog.lessons_completed) >= 3 and "hat_trick" not in prog.badges:
            prog.badges.append("hat_trick")
        if prog.xp >= 500 and "level_2" not in prog.badges:
            prog.badges.append("level_2")

    @staticmethod
    def _update_detection_score(prog: AwarenessProgress) -> None:
        received = len(prog.campaigns_clicked) + len(prog.campaigns_reported)
        if received == 0:
            return
        prog.detection_score = round(len(prog.campaigns_reported) / received * 100, 1)

    # ── Progress ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_progress(user_id: str) -> AwarenessProgress:
        return _get_or_create_progress(user_id)

    # ── Simulated campaigns ──────────────────────────────────────────────────

    @staticmethod
    def create_campaign(data: CampaignCreate, created_by: str) -> SimulatedCampaign:
        cid = str(uuid.uuid4())
        camp = SimulatedCampaign(
            id=cid,
            name=data.name,
            description=data.description,
            template_subject=data.template_subject,
            template_body=data.template_body,
            target_user_ids=data.target_user_ids,
            total_sent=len(data.target_user_ids),
            created_by=created_by,
            created_at=_now(),
        )
        _campaigns[cid] = camp
        return camp

    @staticmethod
    def list_campaigns() -> List[SimulatedCampaign]:
        return list(_campaigns.values())

    @staticmethod
    def record_click(campaign_id: str, user_id: str) -> None:
        camp = _campaigns.get(campaign_id)
        if camp:
            camp.click_count += 1
        prog = _get_or_create_progress(user_id)
        if campaign_id not in prog.campaigns_clicked:
            prog.campaigns_clicked.append(campaign_id)
        AwarenessService._update_detection_score(prog)

    @staticmethod
    def record_report(campaign_id: str, user_id: str) -> None:
        camp = _campaigns.get(campaign_id)
        if camp:
            camp.report_count += 1
        prog = _get_or_create_progress(user_id)
        if campaign_id not in prog.campaigns_reported:
            prog.campaigns_reported.append(campaign_id)
            prog.xp += 50  # bonus XP for reporting
            AwarenessService._check_badges(prog)
        AwarenessService._update_detection_score(prog)

    # ── Leaderboard ───────────────────────────────────────────────────────────

    @staticmethod
    def leaderboard(limit: int = 20) -> List[LeaderboardEntry]:
        from auth.service import _users_by_id

        entries = []
        for uid, prog in _progress.items():
            user = _users_by_id.get(uid)
            display = user.full_name if user else uid[:8]
            entries.append(
                LeaderboardEntry(
                    rank=0,
                    user_id=uid,
                    display_name=display,
                    xp=prog.xp,
                    lessons_completed=len(prog.lessons_completed),
                    campaigns_reported=len(prog.campaigns_reported),
                    detection_score=prog.detection_score,
                )
            )
        entries.sort(key=lambda e: (-e.xp, -e.detection_score))
        for i, e in enumerate(entries[:limit], start=1):
            e.rank = i
        return entries[:limit]
