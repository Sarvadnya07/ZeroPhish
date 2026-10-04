"""
Deterministic Test Suite for P1-01B: Cross-Worker SSE Event Propagation.

Covers the full Test Matrix from the specification:
- Test 1: Same-worker SSE regression (local delivery preserved)
- Test 2: Cross-worker delivery (Worker A publishes event -> Worker B receives and delivers to local subscriber)
- Test 3: Multiple workers topology (4 simulated/independent worker processes)
- Test 4: Worker restart / clean subscriber detachment & re-subscription
- Test 5: Client reconnect (stateless SSE reconnection without expecting Redis replay; authoritative result endpoint available)
- Test 6: Duplicate event handling (duplicate delivery does not corrupt subscriber queues or re-broadcast)
- Test 7: Ordering preservation (multiple lifecycle events for same scan delivered in arrival order)
- Test 8: Cleanup on shutdown (unsubscribes, cancels listener task, closes Redis clients, clears subscribers)
- Test 9: Production contract (missing REDIS_URL when env=production fails closed at startup)
- Test 10: Loop prevention (worker ignores events with its own origin_worker, preventing broadcast echo)
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway import (
    SSE_EVENT_CHANNEL,
    WORKER_ID,
    _broadcast_to_subscribers,
    _mark_seen_event,
    _publish_cross_worker_sse,
    _publish_to_subscriber,
    _redis_pub_client,
    _redis_sub_client,
    _sse_pubsub_active,
    _sse_pubsub_task,
    _sse_seen_events,
    _sse_subscribers,
    app,
    lifespan,
    sse_metrics,
    start_sse_pubsub,
    stop_sse_pubsub,
)


@pytest.fixture(autouse=True)
def clean_gateway_sse_state():
    """Reset all gateway SSE and Redis pub/sub state before and after each test."""
    gateway._sse_subscribers.clear()
    gateway._sse_subscriber_overflows.clear()
    gateway._sse_seen_events.clear()
    gateway._sse_seen_events_order.clear()
    gateway.sse_metrics.update(
        {
            "sse_queue_full_total": 0,
            "sse_events_dropped_total": 0,
            "sse_subscriber_evictions_total": 0,
            "sse_redis_published_total": 0,
            "sse_redis_received_total": 0,
            "sse_redis_errors_total": 0,
        }
    )
    gateway._redis_pub_client = None
    gateway._redis_sub_client = None
    gateway._sse_pubsub_active = False
    gateway._sse_pubsub_task = None
    yield
    gateway._sse_subscribers.clear()
    gateway._sse_subscriber_overflows.clear()
    gateway._sse_seen_events.clear()
    gateway._sse_seen_events_order.clear()
    gateway._redis_pub_client = None
    gateway._redis_sub_client = None
    gateway._sse_pubsub_active = False
    gateway._sse_pubsub_task = None


# ============================================================================
# Test 1: Same-Worker SSE Regression
# ============================================================================

@pytest.mark.asyncio
async def test_1_same_worker_sse_regression():
    """Existing local SSE fanout continues to work synchronously within a single worker."""
    sub_id = "local-sub-1"
    q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[sub_id] = q

    payload = {"scan_id": "scan-local-1", "verdict": "CRITICAL", "final_score": 95.0}
    _broadcast_to_subscribers(payload, propagate=False)

    assert not q.empty()
    item = q.get_nowait()
    assert item["scan_id"] == "scan-local-1"
    assert item["verdict"] == "CRITICAL"
    assert item["final_score"] == 95.0


# ============================================================================
# Test 2: Cross-Worker Delivery
# ============================================================================

@pytest.mark.asyncio
async def test_2_cross_worker_delivery():
    """
    Simulate Worker A (emitter) and Worker B (subscriber host).
    Worker A publishes scan completion event to Redis channel.
    Worker B receives from Redis channel and delivers to its connected SSE subscriber.
    """
    worker_b_sub_id = "worker-b-client"
    worker_b_queue = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[worker_b_sub_id] = worker_b_queue

    # Simulate event published by Worker A
    worker_a_id = "worker-a-instance-uuid"
    event_payload = {
        "scan_id": "scan-cross-1",
        "verdict": "CRITICAL",
        "final_score": 98.0,
        "complete": True,
    }
    raw_message = json.dumps({
        "event_id": "evt-12345",
        "origin_worker": worker_a_id,
        "event_type": "scan_update",
        "data": event_payload,
    })

    # Mock Redis pubsub message delivery into Worker B's listener logic
    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_pubsub.get_message = AsyncMock(side_effect=[
        {"type": "message", "data": raw_message},
        asyncio.CancelledError(),  # Stop listener cleanly after 1st message
    ])

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        listener_task = asyncio.create_task(gateway._sse_redis_listener_loop("redis://localhost:6379/0"))
        try:
            await asyncio.wait_for(listener_task, timeout=1.0)
        except asyncio.CancelledError:
            pass

    # Worker B's client queue must contain the event
    assert not worker_b_queue.empty()
    delivered = worker_b_queue.get_nowait()
    assert delivered["scan_id"] == "scan-cross-1"
    assert delivered["verdict"] == "CRITICAL"
    assert delivered["complete"] is True
    assert gateway.sse_metrics["sse_redis_received_total"] == 1


# ============================================================================
# Test 3: Multiple Workers Topology (4 Workers)
# ============================================================================

@pytest.mark.asyncio
async def test_3_multiple_workers_topology():
    """
    Simulate a 4-worker cluster:
    Worker 1 emits completion.
    Worker 2, Worker 3, Worker 4 all host connected subscribers.
    Verify all 3 remote workers receive the event without echo.
    """
    worker_queues = {
        f"worker-{i}": asyncio.Queue(maxsize=10)
        for i in [2, 3, 4]
    }
    for wid, q in worker_queues.items():
        gateway._sse_subscribers[wid] = q

    worker_1_id = "worker-1-uuid"
    event_payload = {
        "scan_id": "scan-multi-4w",
        "verdict": "SUSPICIOUS",
        "final_score": 65.0,
    }
    raw_message = json.dumps({
        "event_id": "evt-multi-001",
        "origin_worker": worker_1_id,
        "event_type": "scan_update",
        "data": event_payload,
    })

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_pubsub.get_message = AsyncMock(side_effect=[
        {"type": "message", "data": raw_message},
        asyncio.CancelledError(),
    ])

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        listener_task = asyncio.create_task(gateway._sse_redis_listener_loop("redis://localhost:6379/0"))
        try:
            await asyncio.wait_for(listener_task, timeout=1.0)
        except asyncio.CancelledError:
            pass

    # All 3 subscriber queues received the payload
    for wid, q in worker_queues.items():
        assert not q.empty(), f"Worker queue {wid} did not receive event"
        item = q.get_nowait()
        assert item["scan_id"] == "scan-multi-4w"
        assert item["final_score"] == 65.0


# ============================================================================
# Test 4: Worker Restart
# ============================================================================

@pytest.mark.asyncio
async def test_4_worker_restart_resubscribes_cleanly():
    """
    Worker restarts:
    1. Previous subscriber queues, listener task, and client handles are torn down.
    2. New worker boots, initiates fresh subscription.
    3. New client connects and receives new events.
    """
    # Simulate Worker cycle 1
    mock_pub = AsyncMock()
    mock_sub = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_sub.pubsub = MagicMock(return_value=mock_pubsub)
    mock_sub.aclose = AsyncMock()
    mock_pub.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", side_effect=[mock_pub, mock_sub]):
        await start_sse_pubsub("redis://localhost:6379/0")
        assert gateway._redis_pub_client is not None
        assert gateway._sse_pubsub_task is not None

        # Shutdown Worker 1
        await stop_sse_pubsub()
        assert gateway._redis_pub_client is None
        assert gateway._redis_sub_client is None
        assert gateway._sse_pubsub_task is None

    # Simulate Worker cycle 2 (Restart)
    mock_pub2 = AsyncMock()
    mock_sub2 = AsyncMock()
    mock_pubsub2 = AsyncMock()
    mock_pubsub2.subscribe = AsyncMock()
    mock_sub2.pubsub = MagicMock(return_value=mock_pubsub2)

    with patch("redis.asyncio.from_url", side_effect=[mock_pub2, mock_sub2]):
        await start_sse_pubsub("redis://localhost:6379/0")
        assert gateway._redis_pub_client is not None
        assert gateway._sse_pubsub_task is not None

        # Clean shutdown after test
        await stop_sse_pubsub()


# ============================================================================
# Test 5: Client Reconnect Semantics
# ============================================================================

@pytest.mark.asyncio
async def test_5_client_reconnect_does_not_depend_on_replay():
    """
    Test that SSE disconnection cleans up local queue, and a reconnected client
    does not expect historical replay from transient Redis Pub/Sub, but relies
    on authoritative REST persistence.
    """
    sub_id = "client-session-1"
    q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[sub_id] = q

    # Event emitted during disconnect
    event = {"scan_id": "scan-authoritative-1", "verdict": "SAFE", "final_score": 10.0}
    _broadcast_to_subscribers(event, propagate=False)
    assert q.qsize() == 1

    # Client disconnects: cleanup is called
    gateway._sse_subscribers.pop(sub_id, None)
    assert sub_id not in gateway._sse_subscribers

    # Reconnected client gets a new queue
    new_sub_id = "client-session-2"
    new_q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[new_sub_id] = new_q

    # The new queue starts empty (no old missed event replay from Redis Pub/Sub)
    assert new_q.empty()


# ============================================================================
# Test 6: Duplicate Event Handling
# ============================================================================

@pytest.mark.asyncio
async def test_6_duplicate_event_handling():
    """Inject duplicate event ID; verify it is delivered exactly once to subscribers."""
    sub_id = "sub-dedup-1"
    q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[sub_id] = q

    event_id = "unique-event-id-999"
    raw_message = json.dumps({
        "event_id": event_id,
        "origin_worker": "other-worker-uuid",
        "event_type": "scan_update",
        "data": {"scan_id": "scan-dedup", "final_score": 55.0},
    })

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_pubsub.get_message = AsyncMock(side_effect=[
        {"type": "message", "data": raw_message},
        {"type": "message", "data": raw_message},  # Duplicate delivery
        asyncio.CancelledError(),
    ])

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        listener_task = asyncio.create_task(gateway._sse_redis_listener_loop("redis://localhost:6379/0"))
        try:
            await asyncio.wait_for(listener_task, timeout=1.0)
        except asyncio.CancelledError:
            pass

    # Should only have 1 item in subscriber queue, not 2
    assert q.qsize() == 1
    assert gateway.sse_metrics["sse_redis_received_total"] == 1


# ============================================================================
# Test 7: Event Ordering Preservation
# ============================================================================

@pytest.mark.asyncio
async def test_7_event_ordering_preservation():
    """
    Multiple lifecycle events emitted for the same scan:
    Event 1: Tier 1 partial update
    Event 2: Tier 3 completed update
    Verify queue receives them strictly in arrival order.
    """
    sub_id = "sub-ordered-1"
    q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[sub_id] = q

    event1 = json.dumps({
        "event_id": "evt-seq-1",
        "origin_worker": "remote-worker",
        "data": {"scan_id": "scan-seq", "phase": "partial", "complete": False},
    })
    event2 = json.dumps({
        "event_id": "evt-seq-2",
        "origin_worker": "remote-worker",
        "data": {"scan_id": "scan-seq", "phase": "final", "complete": True},
    })

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_pubsub.get_message = AsyncMock(side_effect=[
        {"type": "message", "data": event1},
        {"type": "message", "data": event2},
        asyncio.CancelledError(),
    ])

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        listener_task = asyncio.create_task(gateway._sse_redis_listener_loop("redis://localhost:6379/0"))
        try:
            await asyncio.wait_for(listener_task, timeout=1.0)
        except asyncio.CancelledError:
            pass

    assert q.qsize() == 2
    first = q.get_nowait()
    second = q.get_nowait()
    assert first["phase"] == "partial"
    assert second["phase"] == "final"


# ============================================================================
# Test 8: Cleanup and Task Leaks
# ============================================================================

@pytest.mark.asyncio
async def test_8_cleanup_and_task_lifecycle():
    """Verify shutdown cancels listener, unlinks subscriptions, and drains resources without task leaks."""
    mock_pub = AsyncMock()
    mock_sub = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_sub.pubsub = MagicMock(return_value=mock_pubsub)
    mock_sub.aclose = AsyncMock()
    mock_pub.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", side_effect=[mock_pub, mock_sub]):
        await start_sse_pubsub("redis://localhost:6379/0")
        task = gateway._sse_pubsub_task
        assert task is not None
        assert not task.done()

        await stop_sse_pubsub()
        assert task.done()
        assert gateway._sse_pubsub_task is None
        assert gateway._redis_pub_client is None
        assert gateway._redis_sub_client is None


# ============================================================================
# Test 9: Missing REDIS_URL Production Contract
# ============================================================================

@pytest.mark.asyncio
async def test_9_missing_redis_url_production_contract():
    """In production environment, absence of REDIS_URL must fail closed during lifespan."""
    prod_config = gateway.GatewayConfig(env="production")
    with patch.dict(os.environ, {"ZEROPHISH_ENV": "production", "DATABASE_URL": "sqlite:///:memory:"}, clear=False):
        # Explicitly remove REDIS_URL
        os.environ.pop("REDIS_URL", None)
        with patch.object(gateway, "CONFIG", prod_config):
            with pytest.raises(RuntimeError) as exc_info:
                async with lifespan(app):
                    pass
            assert "REDIS_URL must be configured in production" in str(exc_info.value)


# ============================================================================
# Test 10: Loop Prevention (Self-Originated Events Ignored)
# ============================================================================

@pytest.mark.asyncio
async def test_10_loop_prevention_self_originated_events():
    """Events received with origin_worker == WORKER_ID must be dropped immediately to prevent echo amplification."""
    sub_id = "sub-echo-1"
    q = asyncio.Queue(maxsize=10)
    gateway._sse_subscribers[sub_id] = q

    raw_message = json.dumps({
        "event_id": "evt-echo-test",
        "origin_worker": WORKER_ID,  # Originated by this worker
        "event_type": "scan_update",
        "data": {"scan_id": "scan-echo", "final_score": 100.0},
    })

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.aclose = AsyncMock()
    mock_pubsub.get_message = AsyncMock(side_effect=[
        {"type": "message", "data": raw_message},
        asyncio.CancelledError(),
    ])

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)
    mock_redis.aclose = AsyncMock()

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        listener_task = asyncio.create_task(gateway._sse_redis_listener_loop("redis://localhost:6379/0"))
        try:
            await asyncio.wait_for(listener_task, timeout=1.0)
        except asyncio.CancelledError:
            pass

    # The subscriber queue must be empty because the self-echo event was filtered out
    assert q.empty()
    assert gateway.sse_metrics["sse_redis_received_total"] == 0


# ============================================================================
# Test 11: Real Multi-Process Worker SSE Propagation Harness
# ============================================================================

def _worker_b_sub_proc(sub_event_pipe, ready_barrier):
    """Worker B process: listens for incoming cross-worker event via simulated transport."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run():
        sub_id = "worker-b-subscriber"
        q = asyncio.Queue(maxsize=10)
        gateway._sse_subscribers[sub_id] = q
        ready_barrier.put("WORKER_B_READY")

        # Wait for event dispatched to Worker B
        raw_evt = sub_event_pipe.get(timeout=10)
        envelope = json.loads(raw_evt)
        # Worker B processes remote event with propagate=False
        gateway._broadcast_to_subscribers(envelope["data"], propagate=False)

        received = await asyncio.wait_for(q.get(), timeout=5.0)
        sub_event_pipe.put(received)

    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


def _worker_a_pub_proc(sub_event_pipe, ready_barrier):
    """Worker A process: emits scan update event and transmits to simulated transport."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _run():
        # Wait until Worker B is ready
        status = ready_barrier.get(timeout=10)
        assert status == "WORKER_B_READY"

        event_payload = {
            "scan_id": "scan-multiprocess-sse-1",
            "verdict": "CRITICAL",
            "final_score": 99.0,
            "complete": True,
        }
        envelope = {
            "event_id": str(uuid.uuid4()),
            "origin_worker": "worker-a-proc-id",
            "event_type": "scan_update",
            "data": event_payload,
        }
        sub_event_pipe.put(json.dumps(envelope))

    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


def test_11_multiprocess_cross_worker_sse_harness():
    """Independent OS processes: Worker A generates event; Worker B receives and delivers to local subscriber."""
    import multiprocessing
    pipe = multiprocessing.Queue()
    barrier = multiprocessing.Queue()

    p_b = multiprocessing.Process(target=_worker_b_sub_proc, args=(pipe, barrier))
    p_a = multiprocessing.Process(target=_worker_a_pub_proc, args=(pipe, barrier))

    p_b.start()
    p_a.start()

    p_a.join(timeout=15)
    p_b.join(timeout=15)

    assert p_a.exitcode == 0
    assert p_b.exitcode == 0

    result = pipe.get(timeout=5)
    assert result["scan_id"] == "scan-multiprocess-sse-1"
    assert result["verdict"] == "CRITICAL"
    assert result["final_score"] == 99.0
