from __future__ import annotations
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from gateway_circuit_wrapper import execute_tier3_with_circuit_breaker
from incidents.models import Incident, IncidentSeverity, IncidentStatus
from infrastructure.database import Base
from repositories.sql_repositories import SQLIncidentRepository
from security.middleware import is_safe_url, is_safe_webhook_url
from tier_2.analyzer import ThreatAnalyzer

@pytest.mark.parametrize(
    'host_str',
    [
        '127.0.0.1',
        'localhost',
        '0.0.0.0',
        '10.0.0.1',
        '10.255.255.254',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.0.1',
        '192.168.1.254',
        '169.254.169.254',
        '100.64.0.1',
        '2130706433',
        '0x7f000001',
        '0177.0.0.1',
        '[::1]',
        '[fe80::1]',
        '[fc00::1]',
        '[::ffff:127.0.0.1]',
    ],
)
def test_ssrf_adversarial_ip_formats_blocked(host_str: str):
    url = f'http://{host_str}/endpoint'
    assert is_safe_webhook_url(url, allow_http=True) is False
    assert is_safe_url(url, allow_http=True) is False

def test_ssrf_dangerous_schemes_and_credentials_blocked():
    assert is_safe_url('file:///etc/passwd', allow_http=True) is False
    assert is_safe_url('ftp://ftp.example.com/test', allow_http=True) is False
    assert is_safe_url('javascript:alert(1)', allow_http=True) is False
    assert is_safe_url('data:text/html,test', allow_http=True) is False
    assert is_safe_url('http://user:password@example.com/', allow_http=True) is False

@pytest.mark.asyncio
async def test_ssrf_multi_hop_redirect_to_private_ip_blocked():
    resp_302 = httpx.Response(
        302,
        headers={'Location': 'http://127.0.0.1/admin/internal'},
        request=httpx.Request('HEAD', 'https://public-service.example.org/tracker'),
    )
    with patch('httpx.AsyncClient.head', new_callable=AsyncMock) as mock_head:
        mock_head.return_value = resp_302
        final_url, flags = await ThreatAnalyzer.track_redirects('https://public-service.example.org/tracker')
        assert 'ssrf_blocked' in flags
        assert '127.0.0.1' not in final_url

@pytest.mark.asyncio
async def test_failure_injection_gemini_timeout_fallback():
    cb = CircuitBreaker(failure_threshold=2, timeout=10.0)
    result = await execute_tier3_with_circuit_breaker(
        body='Urgent: Click here to verify account credentials',
        circuit_breaker=cb,
        tier3_timeout=1,
    )
    assert result.status.value in ('unavailable', 'timeout', 'failed', 'circuit_open')
    assert result.score == 50
    assert result.confidence == 0.0

@pytest.mark.asyncio
async def test_failure_injection_gemini_rate_limit_trips_circuit_breaker():
    cb = CircuitBreaker(failure_threshold=2, timeout=30.0)
    async def mock_failing_gemini():
        raise RuntimeError('HTTP 429 Resource Exhausted')

    # Failure 1
    with pytest.raises(RuntimeError):
        await cb.call(mock_failing_gemini)
    assert cb.state.value == 'closed'
    assert cb._failure_count == 1

    # Failure 2 -> trips to OPEN
    with pytest.raises(RuntimeError):
        await cb.call(mock_failing_gemini)
    assert cb.state.value == 'open'

    # Call 3 -> Rejection via CircuitBreakerOpenError without invoking failing upstream
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call(mock_failing_gemini)

    # Call 4 -> With fallback provided, returns fallback cleanly without raising
    async def mock_fallback():
        return {'verdict': 'SAFE', 'confidence': 0.5}

    fb_result = await cb.call(mock_failing_gemini, fallback=mock_fallback)
    assert fb_result['verdict'] == 'SAFE'
    assert fb_result['confidence'] == 0.5

def test_persistence_across_process_restart():
    tmp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    tmp_db.close()
    db_path = Path(tmp_db.name)
    db_url = f'sqlite:///{db_path}'
    try:
        engine1 = create_engine(db_url)
        Base.metadata.create_all(bind=engine1)
        session_factory1 = sessionmaker(autocommit=False, autoflush=False, bind=engine1)
        repo1 = SQLIncidentRepository(session_factory1)
        incident = Incident(
            id='inc_acceptance_999',
            title='Suspicious phishing campaign',
            description='Urgent spoofing attempt targeting employee credentials',
            sender='attacker@spoofed-phish.net',
            subject='Urgent: Verify Your Account',
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            final_score=92.0,
            evidence=['punycode', 'urgency_cues'],
        )
        created = repo1.save(incident)
        assert created.id == 'inc_acceptance_999'
        engine1.dispose()

        engine2 = create_engine(db_url)
        session_factory2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
        repo2 = SQLIncidentRepository(session_factory2)
        recovered = repo2.get_by_id('inc_acceptance_999')
        assert recovered is not None
        assert recovered.id == 'inc_acceptance_999'
        assert recovered.sender == 'attacker@spoofed-phish.net'
        assert recovered.severity == IncidentSeverity.HIGH
        assert recovered.final_score == 92.0
        assert 'punycode' in recovered.evidence
        engine2.dispose()
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass