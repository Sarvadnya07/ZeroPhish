"""Security awareness service."""
from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional

from .models import (
    AwarenessProgress,
    CampaignCreate,
    CampaignStatus,
    Lesson,
    LessonCreate,
    LeaderboardEntry,
    QuizQuestion,
    QuizSubmit,
    SimulatedCampaign,
)

_lessons: Dict[str, Lesson] = {}
_campaigns: Dict[str, SimulatedCampaign] = {}
_progress: Dict[str, AwarenessProgress] = {}   # user_id → progress


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

    lessons_data = [
        {
            "title": "Recognising Phishing Emails",
            "description": "Learn the hallmarks of a phishing email and how to spot them.",
            "difficulty": "beginner",
            "category": "phishing",
            "content_md": """
## What is Phishing?
Phishing is a cyberattack using deceptive emails to steal credentials or install malware.

## Red Flags
- **Urgency** — "Act now or your account will be closed"
- **Mismatched sender** — display name says PayPal but the real address is paypal@suspicious-xyz.com
- **Suspicious links** — hover over links before clicking; watch for typosquatting (paypa1.com)
- **Grammar errors** — professional organisations proofread their emails

## What to do
1. Don't click links — go directly to the website
2. Verify the sender domain
3. Report it via the ZeroPhish side panel
""",
            "quiz": [
                QuizQuestion(id="q1", question="Which is the clearest sign of phishing?",
                             options=["Colourful images", "Urgent language demanding immediate action",
                                      "A personalized greeting", "An unsubscribe link"],
                             correct_index=1, explanation="Urgency is the #1 phishing tactic."),
                QuizQuestion(id="q2", question="What should you do before clicking a link in an email?",
                             options=["Click it quickly", "Hover over it to reveal the real URL",
                                      "Forward to a friend", "Print the email"],
                             correct_index=1, explanation="Always inspect the actual URL before clicking."),
            ],
            "xp_reward": 100,
            "estimated_minutes": 8,
        },
        {
            "title": "Spear Phishing & BEC",
            "description": "Advanced targeted attacks — Business Email Compromise and personalised spear phishing.",
            "difficulty": "intermediate",
            "category": "spear_phishing",
            "content_md": """
## Spear Phishing
Unlike bulk phishing, spear phishing is targeted at a specific person using personalised information
gathered from LinkedIn, social media, or data breaches.

## Business Email Compromise (BEC)
Attackers impersonate executives or vendors to authorise fraudulent wire transfers.

### Example
> From: ceo@company-secure.net  
> To: accounting@company.com  
> Subject: Urgent wire transfer needed

## Defences
- Verify financial requests via a secondary channel (phone call)
- Enable DMARC / SPF / DKIM on your domain
- Use ZeroPhish — our ML model flags impersonation patterns
""",
            "quiz": [
                QuizQuestion(id="q3", question="BEC attacks primarily target which department?",
                             options=["IT Support", "Accounting/Finance", "HR", "Marketing"],
                             correct_index=1, explanation="Attackers target finance teams to authorise payments."),
            ],
            "xp_reward": 150,
            "estimated_minutes": 12,
        },
        {
            "title": "URL & Link Safety",
            "description": "Identify malicious URLs: IP addresses, punycode, URL shorteners, and more.",
            "difficulty": "beginner",
            "category": "phishing",
            "content_md": """
## Safe URL Practices

### IP-based URLs
`http://192.168.1.1/verify` — legitimate sites use domain names, not raw IPs.

### Punycode / Homograph Attacks
`http://xn--pypl-poad.com` = `pȧypal.com` — looks like PayPal but isn't.

### URL Shorteners
`bit.ly/3xAbc` — always expand before clicking (use a preview service).

### Suspicious TLDs
`.zip`, `.tk`, `.xyz`, `.top` — phishing domains often use cheap or free TLDs.
""",
            "quiz": [
                QuizQuestion(id="q4", question="Which URL is most suspicious?",
                             options=["https://paypal.com/login", "http://192.168.0.1/secure",
                                      "https://bank.gov/login", "https://amazon.com/orders"],
                             correct_index=1, explanation="IP-based URLs are a classic phishing indicator."),
            ],
            "xp_reward": 100,
            "estimated_minutes": 7,
        },
    ]

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
            feedback.append({
                "question_id": q.id,
                "correct": is_correct,
                "explanation": q.explanation,
            })

        score_pct = int((correct / max(len(lesson.quiz), 1)) * 100)
        passed    = score_pct >= 70

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
            prog.xp += 50   # bonus XP for reporting
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
            entries.append(LeaderboardEntry(
                rank=0,
                user_id=uid,
                display_name=display,
                xp=prog.xp,
                lessons_completed=len(prog.lessons_completed),
                campaigns_reported=len(prog.campaigns_reported),
                detection_score=prog.detection_score,
            ))
        entries.sort(key=lambda e: (-e.xp, -e.detection_score))
        for i, e in enumerate(entries[:limit], start=1):
            e.rank = i
        return entries[:limit]
