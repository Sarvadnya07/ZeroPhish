"""
Unit tests for Backend/awareness/service.py.
Covers lesson management, quiz evaluations, campaign tracking, and leaderboard rankings.
"""

import pytest

from awareness.models import (
    CampaignCreate,
    LessonCreate,
    LessonDifficulty,
    QuizQuestion,
    QuizSubmit,
)
from awareness.service import AwarenessService, _campaigns, _lessons, _progress


@pytest.fixture(autouse=True)
def clean_awareness_state():
    _progress.clear()
    _campaigns.clear()
    yield
    _progress.clear()
    _campaigns.clear()


def test_awareness_lesson_and_quiz():
    """Test lesson creation, quiz submission with scoring, and progress tracking."""
    lesson_data = LessonCreate(
        title="Identifying Typosquatting",
        description="Learn to spot character substitution in URLs",
        difficulty=LessonDifficulty.BEGINNER,
        category="phishing",
        estimated_minutes=5,
        content_md="# Typosquatting\nLook closely at domain names.",
        quiz=[
            QuizQuestion(
                id="q1",
                question="Which domain is suspicious?",
                options=["paypal.com", "paypa1.com", "google.com", "apple.com"],
                correct_index=1,
                explanation="paypa1 uses character substitution with the digit 1.",
            )
        ],
    )

    lesson = AwarenessService.create_lesson(lesson_data)
    assert lesson.id is not None
    assert lesson.title == "Identifying Typosquatting"

    # Get lesson
    fetched = AwarenessService.get_lesson(lesson.id)
    assert fetched is not None
    assert fetched.title == lesson.title

    # Submit Quiz (Correct answer)
    quiz_res = AwarenessService.submit_quiz(lesson.id, "user-abc", QuizSubmit(answers={"q1": 1}))
    assert quiz_res["passed"] is True
    assert quiz_res["score_pct"] == 100

    # Verify progress
    progress = AwarenessService.get_progress("user-abc")
    assert len(progress.lessons_completed) == 1
    assert progress.xp >= 50

    # Leaderboard
    board = AwarenessService.leaderboard()
    assert len(board) >= 1
    assert board[0].user_id == "user-abc"


def test_awareness_campaign_lifecycle():
    """Test creating and running a simulated phishing campaign."""
    camp_data = CampaignCreate(
        name="Q3 Finance Phishing Drill",
        description="Drill for finance team",
        template_subject="Urgent Payroll Notification",
        template_body="Please review attached invoice.",
        target_user_ids=["u-cfo", "u-analyst"],
    )

    campaign = AwarenessService.create_campaign(camp_data, created_by="admin-1")
    assert campaign.id is not None
    assert campaign.total_sent == 2

    # User clicks link
    AwarenessService.record_click(campaign.id, "u-cfo")
    assert _campaigns[campaign.id].click_count == 1

    # User reports phishing
    AwarenessService.record_report(campaign.id, "u-analyst")
    assert _campaigns[campaign.id].report_count == 1

    # List campaigns
    all_camps = AwarenessService.list_campaigns()
    assert len(all_camps) >= 1
