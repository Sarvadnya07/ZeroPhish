"""
CODEQUALITY-03: Side-effect regression validation for R-3 (_broadcast_to_subscribers).

Before CODEQUALITY-02, _notify_live_dashboard and receive_tier1_report each had
an inline eviction loop. Now both call _broadcast_to_subscribers. These tests
verify the extraction preserved the exact side-effect contract:

- full queue   -> oldest event dropped, newest enqueued, drop metric incremented
- overflow > 5 -> subscriber evicted from both the queue registry and the
                  overflow map, eviction metric incremented
- successful publish resets the overflow counter
- eviction observed from one call site is not visible to the other
  (registry stays consistent — the failure mode the extraction was meant
  to prevent would show up here as inconsistent registry state)

These are behavioral assertions on observable state, not implementation mocks.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway import app, _broadcast_to_subscribers, _publish_to_subscriber


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_registry():
    gateway._sse_subscribers.clear()
    gateway._sse_subscriber_overflows.clear()
    gateway.sse_metrics.update(
        {
            "sse_queue_full_total": 0,
            "sse_events_dropped_total": 0,
            "sse_subscriber_evictions_total": 0,
        }
    )
    yield
    gateway._sse_subscribers.clear()
    gateway._sse_subscriber_overflows.clear()


def _register(queue_size: int = 2) -> str:
    sub_id = f"sub-{len(gateway._sse_subscribers) + 1}"
    gateway._sse_subscribers[sub_id] = asyncio.Queue(maxsize=queue_size)
    return sub_id


class TestHealthyPublish:
    def test_payload_delivered_and_overflow_reset(self):
        sub_id = _register()
        gateway._sse_subscriber_overflows[sub_id] = 3

        _broadcast_to_subscribers({"event": 1})

        assert gateway._sse_subscribers[sub_id].get_nowait() == {"event": 1}
        # Successful publish resets the overflow counter to 0.
        assert gateway._sse_subscriber_overflows[sub_id] == 0

    def test_all_subscribers_receive_in_registry_order(self):
        s1, s2 = _register(), _register()

        _broadcast_to_subscribers({"event": 1})

        assert gateway._sse_subscribers[s1].get_nowait() == {"event": 1}
        assert gateway._sse_subscribers[s2].get_nowait() == {"event": 1}


class TestBackpressureSideEffects:
    def test_full_queue_drops_oldest_keeps_newest(self):
        sub_id = _register(queue_size=2)
        gateway._sse_subscribers[sub_id].put_nowait({"old": 1})
        gateway._sse_subscribers[sub_id].put_nowait({"old": 2})

        _broadcast_to_subscribers({"new": 3})

        q = gateway._sse_subscribers[sub_id]
        assert q.get_nowait() == {"old": 2}  # oldest dropped
        assert q.get_nowait() == {"new": 3}  # newest present
        assert gateway.sse_metrics["sse_queue_full_total"] == 1
        assert gateway.sse_metrics["sse_events_dropped_total"] == 1

    def test_repeated_overflow_evicts_subscriber(self):
        """Characterizes the pre-refactor policy: >5 overflows -> eviction."""
        sub_id = _register(queue_size=1)
        gateway._sse_subscribers[sub_id].put_nowait({"seed": True})

        for i in range(6):  # MAX_OVERFLOW_THRESHOLD is 5; 6th overflow evicts
            _broadcast_to_subscribers({"n": i})

        assert sub_id not in gateway._sse_subscribers
        assert sub_id not in gateway._sse_subscriber_overflows
        assert gateway.sse_metrics["sse_subscriber_evictions_total"] >= 1

    def test_evicted_subscriber_not_leaked_to_other_broadcasts(self):
        """The failure mode R-3 prevents: one site's eviction leaving the
        registry inconsistent for the other call site."""
        sub_id = _register(queue_size=1)
        gateway._sse_subscribers[sub_id].put_nowait({"seed": True})

        # Drive eviction via the endpoint path (receive_tier1_report).
        with TestClient(app) as client:
            for i in range(6):
                client.post("/tier1/report", json={"n": i})

        # Endpoint-path eviction must be visible to direct broadcast callers.
        assert sub_id not in gateway._sse_subscribers
        # And a subsequent broadcast does not resurrect or KeyError on it.
        _broadcast_to_subscribers({"after": 1})  # must not raise

    def test_publish_failure_evicts_without_raising(self):
        """
        A subscriber whose queue surface misbehaves must not break the
        broadcast loop. Characterizes the pre-existing contract: the guarded
        calls are put_nowait/get_nowait on a queue-like object, whose failures
        surface as TypeError/ValueError/RuntimeError (e.g. a Mock with an
        unusable spec). An arbitrary non-queue object raising AttributeError
        was NOT guarded before this refactor and is not asserted here.
        """
        from unittest.mock import Mock

        sub_id = _register()
        broken_queue = Mock(spec=[])  # any attribute access raises AttributeError...
        broken_queue.put_nowait = Mock(side_effect=RuntimeError("surface gone"))
        broken_queue.get_nowait = Mock(side_effect=RuntimeError("surface gone"))
        gateway._sse_subscribers[sub_id] = broken_queue

        _broadcast_to_subscribers({"event": 1})  # must not raise

        assert sub_id not in gateway._sse_subscribers
        assert gateway.sse_metrics["sse_subscriber_evictions_total"] == 1
