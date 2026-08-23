"""
Unit tests for Backend/analytics/service.py.
Covers dashboard summary, user scan history, model metrics updates, policy rules, and false positive flows.
"""
import pytest

from analytics.models import PolicyRuleCreate
from analytics.service import AnalyticsService
from repositories.factory import reset_repositories


@pytest.fixture(autouse=True)
def clean_repos():
    reset_repositories()
    yield
    reset_repositories()


def test_analytics_record_and_summary():
    """Test recording scans and calculating dashboard summary."""
    AnalyticsService.record_scan(
        scan_id="scan-a1",
        sender="attacker@spoofed.com",
        subject="Action required",
        final_score=85.0,
        verdict="CRITICAL",
        category="Credential",
        tier1=30,
        tier2=80,
        tier3=90,
    )

    summary = AnalyticsService.dashboard_summary()
    assert summary.total_scans_today >= 1
    assert summary.critical_today >= 1

    feed = AnalyticsService.threat_feed(limit=10)
    assert len(feed) >= 1
    assert feed[0].id == "scan-a1"

    heatmap = AnalyticsService.threat_heatmap()
    assert len(heatmap) == 168


def test_analytics_false_positive_workflow():
    """Test reporting and reviewing a false positive."""
    fp = AnalyticsService.report_false_positive(
        scan_id="scan-a1",
        reporter_id="user-123",
        reason="Partner newsletter",
        original_score=75.0,
        original_verdict="CRITICAL",
    )
    assert fp.id is not None
    assert fp.reviewed is False

    open_fps = AnalyticsService.list_false_positives(reviewed=False)
    assert any(f.id == fp.id for f in open_fps)

    reviewed_fp = AnalyticsService.review_false_positive(
        fp_id=fp.id,
        reviewer_id="admin-99",
        resolution="Approved benign sender",
    )
    assert reviewed_fp.reviewed is True
    assert reviewed_fp.reviewer_id == "admin-99"


def test_analytics_policy_rules_crud():
    """Test creating, listing, and deleting policy rules."""
    rule_data = PolicyRuleCreate(
        name="Block .top TLD",
        description="Immediate block for .top domains",
        enabled=True,
        condition_type="tld",
        condition_value=".top",
        action="block",
    )

    rule = AnalyticsService.create_policy(rule_data, creator_id="admin-1")
    assert rule.id is not None
    assert rule.name == "Block .top TLD"

    rules = AnalyticsService.list_policies()
    assert any(r.id == rule.id for r in rules)

    assert AnalyticsService.delete_policy(rule.id) is True
    assert not any(r.id == rule.id for r in AnalyticsService.list_policies())


def test_analytics_user_history_and_risk_score():
    """Test user risk score calculation."""
    score = AnalyticsService.user_risk_score("nonexistent-user")
    assert score == 0.0

    history = AnalyticsService.user_scan_history("user-10")
    assert isinstance(history, list)


def test_analytics_model_metrics_update():
    """Test dynamic updates to ML model precision/recall metrics."""
    metrics = AnalyticsService.model_metrics()
    assert metrics.accuracy > 0.90

    AnalyticsService.update_model_metrics(fp_delta=1, fn_delta=1)
    updated_metrics = AnalyticsService.model_metrics()
    assert updated_metrics.last_evaluated is not None
