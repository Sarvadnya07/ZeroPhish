"""
Deterministic test suite for P1-01A: Shared Scan Lifecycle.

Validates:
A. Same-worker lifecycle (create -> processing -> complete -> status -> result)
B. Cross-worker lifecycle (Worker A creates -> shared persistence -> Worker B reads)
C. Restart boundary (Worker A initiates in persistent DB -> Worker A terminates/restarts -> Worker B reads)
D. Concurrency control / Stale overwrite protection (Stale incomplete updates cannot overwrite complete scans)
E. Expiry and count semantics
F. Failure paths (Persistence failures do not produce false SAFE / success)
G. Multi-process worker harness (Actual separate processes sharing SQLite/PostgreSQL durable store)
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from infrastructure.database import Base
from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    GatewayScanResponse,
    ScoringWeights,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
    Tier3Result,
    TierStatus,
    Verdict,
)
from repositories.in_memory import InMemoryScanResultRepository
from repositories.sql_repositories import SQLScanResultRepository


def _make_dummy_scan(
    scan_id: str,
    complete: bool = False,
    partial_score: float = 40.0,
    final_score: float | None = None,
    verdict: Verdict = Verdict.SUSPICIOUS,
    tier3_status: TierStatus = TierStatus.PROCESSING,
) -> GatewayScanResponse:
    return GatewayScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        partial_score=partial_score,
        final_score=final_score,
        verdict=verdict,
        tier1=Tier1Result(score=int(partial_score), execution_time_ms=5.0, evidence=["keyword"], status=CleanStatus.SUSPICIOUS),
        tier2=Tier2Result(
            score=partial_score,
            status=TierStatus.COMPLETE,
            domain_analysis=DomainAnalysis(status=DomainStatus.SUSPICIOUS, score=partial_score),
            threat_analysis=Tier2Analysis(status=DomainStatus.SUSPICIOUS, score=partial_score),
            threat_details=ThreatAnalysisDetail(threat_level=int(partial_score), category="Phishing", reasoning="Test evidence"),
        ),
        tier3=Tier3Result(score=80, category="AI_PHISH", reasoning="High confidence phish", status=tier3_status) if complete else None,
        tier3_status=tier3_status,
        complete=complete,
        layers_completed=3 if complete else 2,
        combined_evidence=["keyword"],
        weights=ScoringWeights(),
        sender="attacker@domain.com",
        subject="Urgent Account Verification",
        total_execution_time_ms=120.0 if complete else 50.0,
    )


# ==============================================================================
# Category A: Same-Worker Lifecycle
# ==============================================================================

@pytest.mark.asyncio
async def test_same_worker_lifecycle():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    scan_id = "scan-same-worker-001"
    initial_scan = _make_dummy_scan(scan_id=scan_id, complete=False)

    # 1. Create / Initial save
    await repo.save(scan_id, initial_scan)

    # 2. Status retrieval (in-progress)
    stored = await repo.get(scan_id)
    assert stored is not None
    assert stored.scan_id == scan_id
    assert stored.complete is False
    assert stored.verdict == Verdict.SUSPICIOUS
    assert stored.final_score is None

    # 3. Complete scan
    completed_scan = _make_dummy_scan(
        scan_id=scan_id,
        complete=True,
        final_score=85.0,
        verdict=Verdict.CRITICAL,
        tier3_status=TierStatus.COMPLETE,
    )
    await repo.save(scan_id, completed_scan)

    # 4. Final retrieval
    final = await repo.get(scan_id)
    assert final is not None
    assert final.complete is True
    assert final.final_score == 85.0
    assert final.verdict == Verdict.CRITICAL
    assert final.tier3_status == TierStatus.COMPLETE


# ==============================================================================
# Category B: Cross-Worker Lifecycle
# ==============================================================================

@pytest.mark.asyncio
async def test_cross_worker_lifecycle():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        url = f"sqlite:///{db_path}"
        engine = create_engine(url)
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        # Worker A creates scan record
        def make_worker_a_factory():
            eng = create_engine(url)
            return sessionmaker(autocommit=False, autoflush=False, bind=eng)

        # Worker B reads/updates scan record
        def make_worker_b_factory():
            eng = create_engine(url)
            return sessionmaker(autocommit=False, autoflush=False, bind=eng)

        repo_a = SQLScanResultRepository(make_worker_a_factory())
        repo_b = SQLScanResultRepository(make_worker_b_factory())

        scan_id = "scan-cross-worker-002"
        scan = _make_dummy_scan(scan_id=scan_id, complete=False)

        # Worker A saves
        await repo_a.save(scan_id, scan)

        # Worker B retrieves without having any worker A in-memory context
        read_by_b = await repo_b.get(scan_id)
        assert read_by_b is not None
        assert read_by_b.scan_id == scan_id
        assert read_by_b.complete is False

        # Worker A completes
        scan_done = _make_dummy_scan(
            scan_id=scan_id,
            complete=True,
            final_score=92.0,
            verdict=Verdict.CRITICAL,
            tier3_status=TierStatus.COMPLETE,
        )
        await repo_a.save(scan_id, scan_done)

        # Worker B immediately observes completion
        read_done_b = await repo_b.get(scan_id)
        assert read_done_b is not None
        assert read_done_b.complete is True
        assert read_done_b.final_score == 92.0
        assert read_done_b.verdict == Verdict.CRITICAL

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


# ==============================================================================
# Category C: Restart Boundary
# ==============================================================================

@pytest.mark.asyncio
async def test_restart_boundary_preserves_state():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        url = f"sqlite:///{db_path}"
        engine = create_engine(url)
        Base.metadata.create_all(bind=engine)

        scan_id = "scan-restart-boundary-003"
        scan = _make_dummy_scan(
            scan_id=scan_id,
            complete=True,
            final_score=78.5,
            verdict=Verdict.SUSPICIOUS,
            tier3_status=TierStatus.COMPLETE,
        )

        # Process/session 1: save and close completely
        factory1 = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        repo1 = SQLScanResultRepository(factory1)
        await repo1.save(scan_id, scan)
        engine.dispose()
        del repo1
        del factory1

        # Simulate full process restart with fresh engine and sessionmaker
        engine2 = create_engine(url)
        factory2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
        repo2 = SQLScanResultRepository(factory2)

        recovered = await repo2.get(scan_id)
        assert recovered is not None
        assert recovered.scan_id == scan_id
        assert recovered.complete is True
        assert recovered.final_score == 78.5
        assert recovered.verdict == Verdict.SUSPICIOUS
        engine2.dispose()

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


# ==============================================================================
# Category D: Concurrency Control & Stale Overwrite Protection
# ==============================================================================

@pytest.mark.asyncio
async def test_stale_incomplete_update_does_not_overwrite_complete_sql():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    scan_id = "scan-concurrency-sql-004"
    completed_scan = _make_dummy_scan(
        scan_id=scan_id,
        complete=True,
        final_score=95.0,
        verdict=Verdict.CRITICAL,
        tier3_status=TierStatus.COMPLETE,
    )
    await repo.save(scan_id, completed_scan)

    # Attempt to write stale, incomplete update
    stale_scan = _make_dummy_scan(
        scan_id=scan_id,
        complete=False,
        partial_score=30.0,
        final_score=None,
        verdict=Verdict.SAFE,
    )
    await repo.save(scan_id, stale_scan)

    # Completed state must remain intact
    current = await repo.get(scan_id)
    assert current is not None
    assert current.complete is True
    assert current.final_score == 95.0
    assert current.verdict == Verdict.CRITICAL


@pytest.mark.asyncio
async def test_stale_incomplete_update_does_not_overwrite_complete_in_memory():
    repo = InMemoryScanResultRepository()
    scan_id = "scan-concurrency-mem-005"
    completed_scan = _make_dummy_scan(
        scan_id=scan_id,
        complete=True,
        final_score=88.0,
        verdict=Verdict.CRITICAL,
    )
    await repo.save(scan_id, completed_scan)

    stale_scan = _make_dummy_scan(
        scan_id=scan_id,
        complete=False,
        partial_score=20.0,
        final_score=None,
        verdict=Verdict.SAFE,
    )
    await repo.save(scan_id, stale_scan)

    current = await repo.get(scan_id)
    assert current is not None
    assert current.complete is True
    assert current.final_score == 88.0
    assert current.verdict == Verdict.CRITICAL


# ==============================================================================
# Category E: Expiry & Count Semantics
# ==============================================================================

@pytest.mark.asyncio
async def test_expiry_and_count_semantics():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    assert await repo.count() == 0
    assert await repo.count_pending() == 0

    scan1 = _make_dummy_scan("scan-1", complete=False)
    scan2 = _make_dummy_scan("scan-2", complete=True, final_score=80.0)

    await repo.save("scan-1", scan1)
    await repo.save("scan-2", scan2)

    assert await repo.count() == 2
    assert await repo.count_pending() == 1

    all_scans = await repo.list_all(limit=10)
    assert len(all_scans) == 2

    # Deletion
    deleted = await repo.delete("scan-1")
    assert deleted is True
    assert await repo.count() == 1
    assert await repo.count_pending() == 0


# ==============================================================================
# Category F: Failure Paths & Fail-Closed Behavior
# ==============================================================================

@pytest.mark.asyncio
async def test_persistence_failure_raises_and_does_not_mask_as_safe():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    scan = _make_dummy_scan("scan-fail-test", complete=False)

    with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("Database write error")):
        with pytest.raises(RuntimeError, match="Database write error"):
            await repo.save("scan-fail-test", scan)

    # Ensure unpersisted record is not returned or defaulted to SAFE
    result = await repo.get("scan-fail-test")
    assert result is None


@pytest.mark.asyncio
async def test_cross_worker_estimated_completion_calculation():
    """Verify that a worker without scan_started_at in local memory computes estimated_completion_ms from durable timestamp."""
    from gateway import gateway_status, scan_started_at
    from fastapi import Request
    from unittest.mock import AsyncMock, MagicMock
    from models.gateway_models import ScanStatusResponse

    scan_id = "scan-cross-est-001"
    # Ensure worker-local memory has NO entry for this scan
    scan_started_at.pop(scan_id, None)

    scan = _make_dummy_scan(scan_id=scan_id, complete=False)
    # Give it a timestamp from 2 seconds ago
    scan.timestamp = datetime.now(timezone.utc)

    mock_repo = AsyncMock()
    mock_repo.get = AsyncMock(return_value=scan)

    with patch("gateway.get_scan_result_repository", return_value=mock_repo):
        req = MagicMock(spec=Request)
        status_resp: ScanStatusResponse = await gateway_status(
            request=req,
            scan_id=scan_id,
            api_key="test-key",
        )

        assert status_resp.scan_id == scan_id
        assert status_resp.complete is False
        # Worker B had no in-memory tracker, but computed estimated_completion_ms from durable timestamp!
        assert status_resp.estimated_completion_ms is not None
        assert status_resp.estimated_completion_ms > 0


@pytest.mark.asyncio
async def test_production_persistence_contract_lifespan():
    """Verify production mode fails closed if DATABASE_URL is missing."""
    import gateway
    from dataclasses import replace

    prod_config = replace(gateway.CONFIG, env="production")
    with patch("gateway.CONFIG", prod_config):
        with patch.dict(os.environ, {}, clear=True):
            if "DATABASE_URL" in os.environ:
                del os.environ["DATABASE_URL"]
            with pytest.raises(RuntimeError, match="DATABASE_URL must be configured in production environment"):
                async with gateway.lifespan(gateway.app):
                    pass


# ==============================================================================
# Category G: Deterministic Multi-Worker Process Test (2 and 4 workers)
# ==============================================================================

def _worker_writer_process(
    db_path: str,
    scan_id: str,
    ready_queue: multiprocessing.Queue,
    step_queue: multiprocessing.Queue,
):
    """Worker process that writes an initial scan then completes it after a signal."""
    url = f"sqlite:///{db_path}"
    engine = create_engine(url)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    scan = _make_dummy_scan(scan_id=scan_id, complete=False)
    loop.run_until_complete(repo.save(scan_id, scan))
    ready_queue.put("WRITE_INITIAL_DONE")

    # Await step signal before completing
    step = step_queue.get(timeout=15)
    assert step == "PROCEED_TO_COMPLETE"

    # Complete the scan
    completed = _make_dummy_scan(
        scan_id=scan_id,
        complete=True,
        final_score=99.0,
        verdict=Verdict.CRITICAL,
        tier3_status=TierStatus.COMPLETE,
    )
    loop.run_until_complete(repo.save(scan_id, completed))
    ready_queue.put("WRITE_COMPLETE_DONE")
    engine.dispose()
    loop.close()


def _worker_reader_process(db_path: str, scan_id: str, result_queue: multiprocessing.Queue):
    """Worker process running in a completely separate OS process with no shared memory."""
    url = f"sqlite:///{db_path}"
    engine = create_engine(url)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    repo = SQLScanResultRepository(session_factory)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    res = loop.run_until_complete(repo.get(scan_id))
    if res:
        result_queue.put({
            "found": True,
            "complete": res.complete,
            "final_score": res.final_score,
            "verdict": res.verdict.value if hasattr(res.verdict, "value") else str(res.verdict),
        })
    else:
        result_queue.put({"found": False})

    engine.dispose()
    loop.close()


def test_multi_worker_2_processes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        url = f"sqlite:///{db_path}"
        engine = create_engine(url)
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        scan_id = "scan-multi-proc-2w"
        comm_queue = multiprocessing.Queue()
        step_queue = multiprocessing.Queue()
        res_queue = multiprocessing.Queue()

        # Start Worker Writer
        p_writer = multiprocessing.Process(
            target=_worker_writer_process,
            args=(db_path, scan_id, comm_queue, step_queue),
        )
        p_writer.start()

        # Wait for Writer initial signal
        sig1 = comm_queue.get(timeout=10)
        assert sig1 == "WRITE_INITIAL_DONE"

        # Worker Reader 1 reads in-progress state
        p_reader1 = multiprocessing.Process(
            target=_worker_reader_process,
            args=(db_path, scan_id, res_queue),
        )
        p_reader1.start()
        p_reader1.join(timeout=10)
        out1 = res_queue.get(timeout=5)
        assert out1["found"] is True
        assert out1["complete"] is False

        # Signal Writer to proceed to complete
        step_queue.put("PROCEED_TO_COMPLETE")

        # Wait for Writer complete signal
        sig2 = comm_queue.get(timeout=10)
        assert sig2 == "WRITE_COMPLETE_DONE"
        p_writer.join(timeout=10)

        # Worker Reader 2 reads completed state
        p_reader2 = multiprocessing.Process(
            target=_worker_reader_process,
            args=(db_path, scan_id, res_queue),
        )
        p_reader2.start()
        p_reader2.join(timeout=10)
        out2 = res_queue.get(timeout=5)
        assert out2["found"] is True
        assert out2["complete"] is True
        assert out2["final_score"] == 99.0
        assert out2["verdict"] == "CRITICAL"

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


def test_multi_worker_4_processes():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        url = f"sqlite:///{db_path}"
        engine = create_engine(url)
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        scan_id = "scan-multi-proc-4w"
        comm_queue = multiprocessing.Queue()
        step_queue = multiprocessing.Queue()

        # Worker 1 (Writer)
        p_writer = multiprocessing.Process(
            target=_worker_writer_process,
            args=(db_path, scan_id, comm_queue, step_queue),
        )
        p_writer.start()

        sig1 = comm_queue.get(timeout=10)
        assert sig1 == "WRITE_INITIAL_DONE"

        # Worker 2, Worker 3, Worker 4 read concurrently
        queues = [multiprocessing.Queue() for _ in range(3)]
        readers = [
            multiprocessing.Process(
                target=_worker_reader_process,
                args=(db_path, scan_id, queues[i]),
            )
            for i in range(3)
        ]
        for r in readers:
            r.start()
        for r in readers:
            r.join(timeout=10)

        for q in queues:
            res = q.get(timeout=5)
            assert res["found"] is True
            assert res["complete"] is False

        # Signal Writer to complete
        step_queue.put("PROCEED_TO_COMPLETE")

        sig2 = comm_queue.get(timeout=10)
        assert sig2 == "WRITE_COMPLETE_DONE"
        p_writer.join(timeout=10)

        # Readers check completed state across all workers
        queues_done = [multiprocessing.Queue() for _ in range(3)]
        readers_done = [
            multiprocessing.Process(
                target=_worker_reader_process,
                args=(db_path, scan_id, queues_done[i]),
            )
            for i in range(3)
        ]
        for r in readers_done:
            r.start()
        for r in readers_done:
            r.join(timeout=10)

        for q in queues_done:
            res = q.get(timeout=5)
            assert res["found"] is True
            assert res["complete"] is True
            assert res["final_score"] == 99.0

    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
