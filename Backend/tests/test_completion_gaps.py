"""
Regression and integration test suite for PRODUCT-02 implementation gaps:
1. Gateway Redis Speed Layer caching and cache endpoints
2. SQL repositories durable persistence (ScanResults, Analytics, Webhooks)
3. Vision Service real image handling and fallback
"""

import asyncio
import base64
import json
import os
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from infrastructure.database import Base
from infrastructure.models import (
    ScanResultDB,
    ScanEventDB,
    FalsePositiveDB,
    PolicyRuleDB,
    WebhookSubscriptionDB,
    WebhookDeliveryDB,
)
from repositories.sql_repositories import (
    SQLScanResultRepository,
    SQLAnalyticsRepository,
    SQLWebhookRepository,
)
from analytics.models import FalsePositiveReport, PolicyRule
from webhooks.models import WebhookSubscription, WebhookDelivery, WebhookEventType
from vision.service import VisionService
from models.gateway_models import (
    GatewayScanResponse,
    ScoringWeights,
    Tier1Result,
    Tier2Result,
    DomainAnalysis,
    Tier2Analysis,
    ThreatAnalysisDetail,
)


@pytest.fixture
def sqlite_session_factory():
    engine = create_engine('sqlite:///:memory:', connect_args={'check_same_thread': False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_sql_scan_result_repository(sqlite_session_factory):
    repo = SQLScanResultRepository(sqlite_session_factory)
    assert repo.count() == 0

    scan = GatewayScanResponse(
        scan_id='scan-test-123',
        timestamp=datetime.now(timezone.utc).isoformat(),
        partial_score=45.0,
        final_score=75.0,
        verdict='CRITICAL',
        complete=True,
        layers_completed=3,
        tier1=Tier1Result(score=50, evidence=['Urgent keyword'], status='Clean'),
        tier2=Tier2Result(
            score=60.0,
            evidence=['Suspicious domain'],
            domain_analysis=DomainAnalysis(status='SUSPICIOUS', score=60.0),
            threat_analysis=Tier2Analysis(status='CRITICAL', score=70.0),
            threat_details=ThreatAnalysisDetail(
                threat_level=70, category='Financial', reasoning='Test', flagged_phrases=[]
            ),
        ),
        tier3=None,
        combined_evidence=['Urgent keyword'],
        weights=ScoringWeights(),
        sender='phish@test.com',
        subject='Urgent Wire',
    )

    repo.save(scan.scan_id, scan)
    assert repo.count() == 1
    assert repo.count_pending() == 0

    retrieved = repo.get('scan-test-123')
    assert retrieved is not None
    assert retrieved.scan_id == 'scan-test-123'
    assert retrieved.verdict == 'CRITICAL'
    assert retrieved.final_score == 75.0

    all_scans = repo.list_all(limit=10)
    assert len(all_scans) == 1

    deleted = repo.delete('scan-test-123')
    assert deleted is True
    assert repo.count() == 0


def test_sql_analytics_repository(sqlite_session_factory):
    repo = SQLAnalyticsRepository(sqlite_session_factory)

    # 1. Record scan events
    repo.record_scan_event({
        'scan_id': 'ev-1',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ts': 1700000000.0,
        'hour': 14,
        'day': 2,
        'sender_domain': 'evil-phish.com',
        'subject': 'Verify account',
        'final_score': 85.0,
        'verdict': 'CRITICAL',
        'category': 'Credential',
        'tier1_score': 80.0,
        'tier2_score': 85.0,
        'tier3_score': 90.0,
    })

    events = repo.get_scan_events(limit=10)
    assert len(events) == 1
    assert events[0]['sender_domain'] == 'evil-phish.com'

    feed = repo.get_threat_feed(limit=5)
    assert len(feed) == 1
    assert feed[0].verdict == 'CRITICAL'

    heatmap = repo.get_threat_heatmap()
    assert len(heatmap) == 168  # 7 days * 24 hours

    # 2. False Positive
    fp = FalsePositiveReport(
        id='fp-1',
        scan_id='ev-1',
        reporter_id='user-1',
        reason='Legitimate company newsletter',
        original_score=85.0,
        original_verdict='CRITICAL',
        reviewed=False,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    repo.save_false_positive(fp)
    assert len(repo.list_false_positives(reviewed=False)) == 1

    reviewed = repo.review_false_positive('fp-1', reviewer_id='admin-1', resolution='Approved as safe')
    assert reviewed.reviewed is True
    assert len(repo.list_false_positives(reviewed=False)) == 0

    # 3. Policy rules
    policy = PolicyRule(
        id='pol-1',
        name='Block suspicious TLD',
        description='Block all .zip TLDs',
        enabled=True,
        condition_type='tld',
        condition_value='.zip',
        action='block',
        created_by='admin-1',
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    repo.save_policy_rule(policy)
    policies = repo.list_policy_rules()
    assert len(policies) == 1
    assert policies[0].name == 'Block suspicious TLD'

    deleted_policy = repo.delete_policy_rule('pol-1')
    assert deleted_policy is True
    assert len(repo.list_policy_rules()) == 0


def test_sql_webhook_repository(sqlite_session_factory):
    repo = SQLWebhookRepository(sqlite_session_factory)

    sub = WebhookSubscription(
        id='sub-1',
        url='https://security.example.com/alerts',
        events=[WebhookEventType.SCAN_CRITICAL],
        secret='hexsecret123',
        enabled=True,
        created_at=datetime.now(timezone.utc).isoformat(),
        owner_id='analyst-1',
        description='SIEM Critical Phishing Alerts',
        headers={'X-Custom-Auth': 'token123'},
    )
    repo.save_subscription(sub)

    subs = repo.list_subscriptions(owner_id='analyst-1')
    assert len(subs) == 1
    assert subs[0].url == 'https://security.example.com/alerts'

    # Delivery log
    deliv = WebhookDelivery(
        id='del-1',
        subscription_id='sub-1',
        event_type=WebhookEventType.SCAN_CRITICAL,
        payload={'scan_id': 's1', 'verdict': 'CRITICAL'},
        status='success',
        http_status=200,
        response_body='{"status":"ok"}',
        attempted_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=45.2,
        retries=0,
    )
    repo.record_delivery(deliv)

    log = repo.get_delivery_log(limit=5)
    assert len(log) == 1
    assert log[0].status == 'success'
    assert log[0].http_status == 200

    assert repo.delete_subscription('sub-1') is True
    assert len(repo.list_subscriptions()) == 0


@pytest.mark.asyncio
async def test_vision_service_offline_fallback():
    # 1x1 transparent PNG data URI
    tiny_png_b64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='

    # Test clean page
    result = await VisionService.analyze_screenshot(
        image_b64=tiny_png_b64,
        url='https://login.microsoftonline.com',
        title='Microsoft Login Official',
    )
    assert 'is_phishing' in result
    assert 'threat_score' in result
    assert result['is_phishing'] is False
    assert result['threat_score'] <= 30.0

    # Test deceptive page
    spoofed = await VisionService.analyze_screenshot(
        image_b64=tiny_png_b64,
        url='http://evil-attacker-portal.xyz/secure',
        title='Microsoft Login - Verify Password',
    )
    assert spoofed['is_phishing'] is True
    assert spoofed['threat_score'] >= 70.0
    assert spoofed['matched_brand'] == 'Microsoft'

    # Test invalid base64
    invalid = await VisionService.analyze_screenshot(
        image_b64='invalid_not_an_image',
    )
    assert invalid['is_phishing'] is False
    assert 'Could not parse image data' in invalid['reasoning']


@pytest.mark.asyncio
async def test_gateway_caching_speed_layer():
    from gateway import _calculate_scan_cache_key
    from repositories.factory import get_cache_backend

    cache = get_cache_backend()
    await cache.clear_prefix("scan:")

    key = _calculate_scan_cache_key("test@example.com", "Test body", ["https://example.com"], "Test Subject")
    assert key.startswith("scan:")

    await cache.set(key, '{"scan_id":"cached-123","verdict":"SAFE","partial_score":10.0}', ttl_seconds=60)
    cached = await cache.get(key)
    assert cached is not None
    assert "cached-123" in cached

    stats = await cache.get_stats()
    assert stats["keys_count"] >= 1

    cleared = await cache.clear_prefix("scan:")
    assert cleared >= 1
    assert await cache.get(key) is None


def test_gateway_cache_endpoints():
    from fastapi.testclient import TestClient
    from gateway import app

    client = TestClient(app)
    stats_res = client.get('/cache/stats')
    assert stats_res.status_code == 200
    assert 'backend' in stats_res.json()

    del_res = client.delete('/cache/clear')
    assert del_res.status_code == 200
    assert del_res.json()['status'] == 'success'

