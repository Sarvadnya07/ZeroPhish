"""
Phase 1.10 final production-readiness regression tests.

These pin the specific defects corrected during the final consolidation pass so
they cannot silently regress:

1. A degraded server Tier 1 evaluation must stay tagged "degraded" even when the
   client supplies a `tier1_score`. Previously the client signal caused the
   server's degradation to be reported as "server_verified".
2. Mutating operational endpoints (`/tier1/report`, `/cache/clear`,
   `/gateway/circuit/reset`) must honour the configured API key. `/tier1/report`
   in particular writes the dashboard's live feed.
3. The SSE subscriber-overflow map must not retain entries for subscribers that
   disconnect normally.
"""

import time

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway import app
from tier_1.engine import ServerTier1Result


@pytest.fixture
def client():
    return TestClient(app)


def _scan_payload(**overrides):
    payload = {
        "sender": "attacker@evil-domain.com",
        "body": "Please verify your account immediately to avoid suspension.",
        "links": [],
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# 1. Degraded server Tier 1 must not be laundered by a client score
# ---------------------------------------------------------------------------

def _degraded_tier1(*args, **kwargs):
    """Simulate an internal Tier 1 failure (fail-safe degraded result)."""
    return ServerTier1Result(
        score=50,
        status="Suspicious",
        category="error",
        evidence=["Tier 1 server-side analysis degraded due to internal error: RuntimeError"],
        execution_time_ms=0.0,
        degraded=True,
    )


def test_client_score_cannot_mask_degraded_server_tier1(client, monkeypatch):
    """
    A client-supplied tier1_score must not upgrade a degraded server evaluation
    to 'server_verified'. The degradation has to remain visible to the fusion
    engine and to operators.
    """
    monkeypatch.setattr(gateway, "analyze_tier1_server", _degraded_tier1)

    resp = client.post(
        "/gateway/scan",
        json=_scan_payload(tier1_score=95, tier1_evidence=["client claims phishing"]),
    )
    assert resp.status_code == 200
    tier1 = resp.json()["tier1"]

    assert tier1["source"] == "degraded", (
        "client input laundered a degraded server Tier 1 into a verified result"
    )
    # The true server score remains separately recorded and unchanged.
    assert tier1["server_score"] == 50
    assert tier1["client_score"] == 95


def test_client_score_can_still_corroborate_a_non_degraded_server(client):
    """
    Regression guard for the intended trust boundary: a client score may
    escalate risk when the server evaluation completed cleanly.
    """
    resp = client.post(
        "/gateway/scan",
        json=_scan_payload(tier1_score=90, tier1_evidence=["client signal"]),
    )
    assert resp.status_code == 200
    tier1 = resp.json()["tier1"]

    assert tier1["source"] in ("corroborated", "server_verified")
    assert tier1["client_score"] == 90
    assert tier1["score"] >= tier1["server_score"]


# ---------------------------------------------------------------------------
# 2. Mutating endpoints honour the configured API key
# ---------------------------------------------------------------------------

def test_tier1_report_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "phase1-10-secret")

    denied = client.post("/tier1/report", json={"scan_id": "s1", "final_score": 1})
    assert denied.status_code == 403

    allowed = client.post(
        "/tier1/report",
        json={"scan_id": "s1", "final_score": 1},
        headers={"X-API-Key": "phase1-10-secret"},
    )
    assert allowed.status_code == 200


def test_cache_clear_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "phase1-10-secret")

    assert client.delete("/cache/clear").status_code == 403
    assert client.delete("/cache/clear", headers={"X-API-Key": "phase1-10-secret"}).status_code == 200


def test_circuit_reset_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "phase1-10-secret")

    assert client.post("/gateway/circuit/reset").status_code == 403
    assert (
        client.post("/gateway/circuit/reset", headers={"X-API-Key": "phase1-10-secret"}).status_code
        == 200
    )


def test_mutating_endpoints_remain_open_when_no_api_key_is_configured(client, monkeypatch):
    """Development default: with no API_KEY configured the gateway is unchanged."""
    monkeypatch.delenv("API_KEY", raising=False)

    assert client.post("/tier1/report", json={"scan_id": "s2"}).status_code == 200
    assert client.post("/gateway/circuit/reset").status_code == 200


# ---------------------------------------------------------------------------
# 3. SSE subscriber bookkeeping does not leak
# ---------------------------------------------------------------------------

def test_sse_subscriber_overflow_map_is_cleaned_on_disconnect(client):
    """
    `_publish_to_subscriber` records an overflow counter for every subscriber it
    delivers to. A subscriber that disconnects must not leave that entry behind,
    otherwise the map grows with subscriber churn for the process lifetime.
    """
    before = set(gateway._sse_subscriber_overflows)

    with client.stream("GET", "/tier1/stream") as response:
        assert response.status_code == 200
        # Drain the initial ping/frame so the subscriber is registered.
        for _ in response.iter_lines():
            break
        # Publishing creates the overflow entry for this subscriber.
        client.post("/tier1/report", json={"scan_id": "sse-leak-probe", "final_score": 7})

    # Exiting the stream context triggers the endpoint's background cleanup.
    new_keys = set(gateway._sse_subscriber_overflows) - before
    assert not new_keys, f"overflow entries leaked after disconnect: {new_keys}"


def test_sse_subscriber_registry_is_empty_after_disconnect(client):
    with client.stream("GET", "/tier1/stream") as response:
        assert response.status_code == 200
        client.post("/tier1/report", json={"scan_id": "sse-reg-probe"})
        assert len(gateway._sse_subscribers) >= 1

    deadline = 20
    for _ in range(deadline):
        if not gateway._sse_subscribers:
            break
        time.sleep(0.05)

    assert not gateway._sse_subscribers, "SSE subscriber registry retained a disconnected client"
