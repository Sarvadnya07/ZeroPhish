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

Note on the SSE coverage: `TestClient` runs the whole ASGI application to
completion before it hands back a response object and only reports
`http.disconnect` after the response has already finished. It therefore can
neither stream nor disconnect an endless SSE response. The SSE regressions below
drive the real application through a controlled ASGI transport
(`_ASGIStreamSession`) and bound every wait explicitly, so a regression fails
loudly instead of hanging the suite.
"""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway import app
from tier_1.engine import ServerTier1Result


@pytest.fixture
def client(monkeypatch):
    """Create an isolated gateway client without running real Tier 3 work.

    These regressions validate Tier 1/API-key/SSE bookkeeping behavior. The
    gateway schedules Tier 3 as a background task, and Starlette TestClient
    waits for BackgroundTasks to finish before completing the request. Running
    the real provider path here couples these unit/regression tests to network
    availability and can block CI indefinitely.
    """
    async def _noop_finalize_tier3(*args, **kwargs):
        return None

    monkeypatch.setattr(gateway, "_finalize_tier3", _noop_finalize_tier3)
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
#
# `TestClient` cannot observe this endpoint: in the installed Starlette the test
# transport runs the entire ASGI application to completion before it hands back a
# response object (`portal.call(self.app, scope, receive, send)` followed by
# `httpx.ByteStream(...)`), and its `receive` only reports `http.disconnect` once
# the response has completed. An endless SSE generator therefore blocks the
# caller forever and a mid-stream disconnect can never be simulated.
#
# The harness below drives the real ASGI application instead, with a
# test-controlled `receive`/`send` pair. Everything on the server side stays
# production code — routing, middleware, the `/tier1/stream` endpoint, the
# subscriber registry, the publisher and the endpoint's `BackgroundTask(cleanup)`.
# Only the network transport is replaced, which is what allows an explicit
# `http.disconnect` and a hard-bounded await of the ASGI call.
# ---------------------------------------------------------------------------

ASGI_SPEC_UVICORN = "2.3"  # what uvicorn (the production server) advertises


class _ASGIStreamSession:
    """A single in-flight ASGI HTTP request whose response chunks are observable."""

    def __init__(
        self,
        method: str,
        path: str,
        *,
        asgi_spec_version: str = ASGI_SPEC_UVICORN,
        body: bytes = b"",
    ):
        self._body = body
        self._request_sent = False
        self._chunk_signal = asyncio.Queue()
        self.disconnected = asyncio.Event()
        self.status_code = None
        self.body_parts = []
        self.response_started = False
        self.response_complete = False
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": asgi_spec_version},
            "http_version": "1.1",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "scheme": "http",
            "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        }

    @property
    def body(self) -> str:
        return "".join(self.body_parts)

    async def receive(self):
        """Deliver the request first; afterwards report only the client disconnect."""
        if not self._request_sent:
            self._request_sent = True
            return {"type": "http.request", "body": self._body, "more_body": False}
        await self.disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(self, message):
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            self.response_started = True
        elif message["type"] == "http.response.body":
            chunk = message.get("body", b"")
            if chunk:
                self.body_parts.append(chunk.decode("utf-8"))
                self._chunk_signal.put_nowait(None)
            if not message.get("more_body", False):
                self.response_complete = True

    async def wait_for(self, marker: str, timeout: float = 5.0) -> str:
        """
        Bounded, event-driven wait until the accumulated body contains `marker`.

        Signal-driven rather than polled: each `send` wakes the waiter, and a
        timeout surfaces as a failure instead of a hang.
        """
        if marker in self.body:
            return self.body
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise AssertionError(f"{marker!r} never arrived on the SSE stream: {self.body!r}")
            await asyncio.wait_for(self._chunk_signal.get(), timeout=remaining)
            if marker in self.body:
                return self.body


def _open_sse_stream(*, asgi_spec_version: str = ASGI_SPEC_UVICORN):
    """Start a real `GET /tier1/stream` request against the gateway application."""
    session = _ASGIStreamSession("GET", "/tier1/stream", asgi_spec_version=asgi_spec_version)
    task = asyncio.create_task(
        app(session.scope, session.receive, session.send), name="GET /tier1/stream"
    )
    return session, task


async def _asgi_json_request(method: str, path: str, payload: dict):
    """Run one complete (non-streaming) request in the same event loop as the stream."""
    session = _ASGIStreamSession(method, path, body=json.dumps(payload).encode())
    await app(session.scope, session.receive, session.send)
    return session.status_code, session.body


async def test_sse_subscriber_overflow_map_is_cleaned_on_disconnect(monkeypatch):
    """
    `_publish_to_subscriber` records an overflow counter for every subscriber it
    delivers to. A subscriber that disconnects must not leave that entry behind,
    otherwise the map grows with subscriber churn for the process lifetime.
    """
    # The report endpoint is only open when no API key is configured.
    monkeypatch.delenv("API_KEY", raising=False)
    before_subscribers = set(gateway._sse_subscribers)
    before_overflows = set(gateway._sse_subscriber_overflows)

    session, stream_task = _open_sse_stream()
    try:
        # 1. The endpoint emitted its initial frame, which also proves the
        #    subscriber was registered.
        initial = await session.wait_for("event: ping")
        assert session.status_code == 200
        assert initial.startswith("event: ping"), initial
        registered = set(gateway._sse_subscribers) - before_subscribers
        assert len(registered) == 1, "SSE stream did not register a subscriber"

        # 2. Publishing through the real endpoint creates the overflow entry and
        #    the event reaches the open stream.
        status, _ = await _asgi_json_request(
            "POST", "/tier1/report", {"scan_id": "sse-leak-probe", "final_score": 7}
        )
        assert status == 200
        assert registered <= set(gateway._sse_subscriber_overflows), (
            "publishing did not record the overflow entry this regression is about"
        )
        await session.wait_for("sse-leak-probe")

        # 3. The client disconnects.
        session.disconnected.set()

        # 4. The endpoint's cleanup runs, the stream ends and the ASGI call
        #    returns; the bound turns a hang into a failure.
        await asyncio.wait_for(stream_task, timeout=5.0)
        assert stream_task.exception() is None
        assert session.response_complete
    finally:
        if not stream_task.done():
            session.disconnected.set()
            stream_task.cancel()

    leaked = set(gateway._sse_subscriber_overflows) - before_overflows
    assert not leaked, f"overflow entries leaked after disconnect: {leaked}"
    assert not (registered & set(gateway._sse_subscribers)), (
        "SSE subscriber registry retained a disconnected client"
    )


async def test_sse_subscriber_registry_is_empty_after_disconnect(monkeypatch):
    """
    The registry is maintained per subscriber: a client that disconnects is
    reaped while an unrelated client stays registered, keeps receiving events,
    and is itself reaped once it disconnects in turn.
    """
    monkeypatch.delenv("API_KEY", raising=False)
    before_subscribers = set(gateway._sse_subscribers)
    before_overflows = set(gateway._sse_subscriber_overflows)

    session_a, task_a = _open_sse_stream()
    session_b, task_b = _open_sse_stream()
    try:
        # Both streams are live and each registered its own subscriber.
        first_a = await session_a.wait_for("event: ping")
        first_b = await session_b.wait_for("event: ping")
        assert first_a.startswith("event: ping") and first_b.startswith("event: ping")
        assert session_a.status_code == session_b.status_code == 200
        registered = set(gateway._sse_subscribers) - before_subscribers
        assert len(registered) == 2, "each SSE stream must register its own subscriber"

        # A publish reaches both subscribers.
        status, _ = await _asgi_json_request("POST", "/tier1/report", {"scan_id": "sse-reg-probe"})
        assert status == 200
        assert registered <= set(gateway._sse_subscriber_overflows)
        await session_a.wait_for("sse-reg-probe")
        await session_b.wait_for("sse-reg-probe")

        # A disconnects: only A is reaped, B is left untouched.
        session_a.disconnected.set()
        await asyncio.wait_for(task_a, timeout=5.0)
        assert task_a.exception() is None
        assert session_a.response_complete
        survivors = registered & set(gateway._sse_subscribers)
        assert len(survivors) == 1, "disconnecting one subscriber reaped the wrong set"

        # B still receives traffic after A is gone, so the dead subscriber did not
        # block unrelated work.
        status, _ = await _asgi_json_request(
            "POST", "/tier1/report", {"scan_id": "sse-post-disconnect"}
        )
        assert status == 200, "a disconnected subscriber blocked an unrelated report"
        await session_b.wait_for("sse-post-disconnect")

        # ...and B is reaped once it disconnects in turn.
        session_b.disconnected.set()
        await asyncio.wait_for(task_b, timeout=5.0)
        assert task_b.exception() is None
        assert session_b.response_complete
    finally:
        for session, task in ((session_a, task_a), (session_b, task_b)):
            if not task.done():
                session.disconnected.set()
                task.cancel()

    assert not (registered & set(gateway._sse_subscribers)), (
        "SSE subscriber registry retained a disconnected client"
    )
    leaked = set(gateway._sse_subscriber_overflows) - before_overflows
    assert not leaked, f"overflow entries leaked after disconnect: {leaked}"


# ---------------------------------------------------------------------------
# 4. ControlledTestProvider produces compliant Tier 3 category with visual check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_controlled_test_provider_visual_check_schema_compliance(monkeypatch):
    """
    Ensure ControlledTestProvider emits a category in LEGITIMATE_AI_CATEGORIES
    when requires_visual_check is True, preventing validation failure to AI_INVALID_RESPONSE.
    """
    monkeypatch.setenv("ZEROPHISH_ENABLE_TEST_PROVIDER", "true")
    from tier_3.providers.test_provider import ControlledTestProvider
    from tier_3.validator import validate_and_normalize_response, LEGITIMATE_AI_CATEGORIES

    provider = ControlledTestProvider()
    assert provider.is_available() is True

    raw_resp = await provider.generate_analysis(
        prompt="VISUAL_CHECK_REQUIRED: Please inspect portal credentials.",
        timeout_sec=2.0,
    )
    assert raw_resp.status.value.upper() == "SUCCESS"

    normalized = validate_and_normalize_response(
        raw_resp,
        original_body="Please inspect portal credentials.",
    )
    assert normalized.category in LEGITIMATE_AI_CATEGORIES
    assert normalized.requires_visual_check is True
    assert normalized.error_category is None
