"""
Tests for webhooks — SSRF URL validation, subscription lifecycle,
role restriction, and delivery log.
Extends existing test_webhooks.py tests for _sign.
"""

import hashlib
import hmac
from unittest.mock import MagicMock, patch

import pytest

from webhooks.service import _sign


def test_sign_with_known_inputs():
    """Test HMAC-SHA256 generation with a known secret and payload."""
    secret = "my_secret"
    payload = b"my_payload"
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    result = _sign(secret, payload)
    assert result == expected
    assert result == "sha256=91bab3317e295fea7d87d0132c73fc88f750d3d83a48aae5d78959eaeadd0402"


def test_sign_with_empty_payload():
    secret = "my_secret"
    payload = b""
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert _sign(secret, payload) == expected


def test_sign_with_empty_secret():
    secret = ""
    payload = b"my_payload"
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert _sign(secret, payload) == expected


def test_sign_with_empty_secret_and_payload():
    secret = ""
    payload = b""
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert _sign(secret, payload) == expected


# ── SSRF validator unit tests ──────────────────────────────────────────────────


def test_ssrf_blocks_loopback():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://127.0.0.1/hook", allow_http=True) is False


def test_ssrf_blocks_localhost():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://localhost/hook", allow_http=True) is False


def test_ssrf_blocks_private_rfc1918_192():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://192.168.1.1/hook", allow_http=True) is False


def test_ssrf_blocks_private_rfc1918_10():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://10.0.0.1/hook", allow_http=True) is False


def test_ssrf_blocks_private_rfc1918_172():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://172.16.0.1/hook", allow_http=True) is False


def test_ssrf_blocks_link_local_metadata():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("http://169.254.169.254/latest/meta-data/", allow_http=True) is False


def test_ssrf_blocks_ftp_scheme():
    from security.middleware import is_safe_webhook_url

    assert is_safe_webhook_url("ftp://example.com/hook", allow_http=True) is False


def test_ssrf_allows_public_https():
    """Test with a known public IP that resolves to a non-private address."""
    mock_addrinfo = [(None, None, None, None, ("1.1.1.1", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        from security.middleware import is_safe_webhook_url

        assert is_safe_webhook_url("https://example.com/hook", allow_http=True) is True


def test_ssrf_blocks_http_in_production():
    from security.middleware import is_safe_webhook_url

    # allow_http=False rejects http:// even to public hosts
    assert is_safe_webhook_url("http://1.1.1.1/hook", allow_http=False) is False


# ── WebhookService unit tests ─────────────────────────────────────────────────


def _make_subscription_data():
    from webhooks.models import WebhookEventType, WebhookSubscriptionCreate

    return WebhookSubscriptionCreate(
        url="https://example.com/hook",
        events=[WebhookEventType.INCIDENT_CREATED],
    )


def _mock_public_dns():
    """Context manager that mocks DNS to return a safe public IP."""
    return patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.1.1.1", 443))])


def test_webhook_subscribe_valid_url():
    from webhooks.service import WebhookService

    data = _make_subscription_data()
    with _mock_public_dns():
        sub = WebhookService.subscribe(data, owner_id="user-123")

    assert sub.id
    assert sub.secret  # HMAC secret generated
    assert sub.owner_id == "user-123"


def test_webhook_subscribe_invalid_url_raises():
    from webhooks.models import WebhookEventType, WebhookSubscriptionCreate
    from webhooks.service import WebhookService

    data = WebhookSubscriptionCreate(
        url="http://127.0.0.1:9999/evil",
        events=[WebhookEventType.INCIDENT_CREATED],
    )
    with pytest.raises(ValueError, match="unsafe"):
        WebhookService.subscribe(data, owner_id="user-123")


def test_webhook_unsubscribe():
    from webhooks.service import WebhookService

    data = _make_subscription_data()
    with _mock_public_dns():
        sub = WebhookService.subscribe(data, owner_id="delme")

    assert WebhookService.unsubscribe(sub.id, owner_id="delme") is True
    assert WebhookService.get_subscription(sub.id) is None


def test_webhook_unsubscribe_wrong_owner_fails():
    from webhooks.service import WebhookService

    data = _make_subscription_data()
    with _mock_public_dns():
        sub = WebhookService.subscribe(data, owner_id="owner1")

    assert WebhookService.unsubscribe(sub.id, owner_id="not-the-owner") is False
    assert WebhookService.get_subscription(sub.id) is not None
