"""
Unit tests for Phase 13.3 External Staging Configuration, Fail-Closed Safety,
Network Timeouts, Finite Retries, Global Runtime Deadlines, and Architecture Integrity.
"""

from pathlib import Path

import pytest

from ml.data.external_staging_client import ExternalStagingRunner
from ml.shadow.staging_config import ExternalStagingConfig, ExternalStagingConfigValidator


def test_config_validation_missing_env(monkeypatch):
    monkeypatch.delenv("ZEROPHISH_ENV", raising=False)
    monkeypatch.delenv("ZEROPHISH_STAGING_BASE_URL", raising=False)
    monkeypatch.delenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", raising=False)

    is_valid, errors, cfg = ExternalStagingConfigValidator.load_and_validate()
    assert is_valid is False
    assert cfg is None
    assert any("ZEROPHISH_ENV is not configured" in e for e in errors)
    assert any("ZEROPHISH_STAGING_BASE_URL is not configured" in e for e in errors)
    assert any("ZEROPHISH_STAGING_ALLOWED_HOSTS is not configured" in e for e in errors)


def test_config_validation_wrong_environment(monkeypatch):
    monkeypatch.setenv("ZEROPHISH_ENV", "production")
    monkeypatch.setenv("ZEROPHISH_STAGING_BASE_URL", "http://staging.local")
    monkeypatch.setenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "staging.local")

    is_valid, errors, cfg = ExternalStagingConfigValidator.load_and_validate()
    assert is_valid is False
    assert any("ZEROPHISH_ENV must be 'staging'" in e for e in errors)


def test_config_validation_production_domain_rejected(monkeypatch):
    monkeypatch.setenv("ZEROPHISH_ENV", "staging")
    monkeypatch.setenv("ZEROPHISH_STAGING_BASE_URL", "https://api.zerophish.com")
    monkeypatch.setenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "api.zerophish.com")

    is_valid, errors, cfg = ExternalStagingConfigValidator.load_and_validate()
    assert is_valid is False
    assert any("Refusing to target production domain" in e for e in errors)


def test_config_validation_host_not_allowlisted(monkeypatch):
    monkeypatch.setenv("ZEROPHISH_ENV", "staging")
    monkeypatch.setenv("ZEROPHISH_STAGING_BASE_URL", "http://unknown-host.com")
    monkeypatch.setenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "staging.example.internal")

    is_valid, errors, cfg = ExternalStagingConfigValidator.load_and_validate()
    assert is_valid is False
    assert any("is not present in ZEROPHISH_STAGING_ALLOWED_HOSTS" in e for e in errors)


def test_config_validation_valid(monkeypatch):
    monkeypatch.setenv("ZEROPHISH_ENV", "staging")
    monkeypatch.setenv("ZEROPHISH_STAGING_BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("ZEROPHISH_STAGING_ALLOWED_HOSTS", "127.0.0.1,localhost")

    is_valid, errors, cfg = ExternalStagingConfigValidator.load_and_validate()
    assert is_valid is True
    assert errors == []
    assert cfg is not None
    assert cfg.zerophish_env == "staging"
    assert cfg.staging_base_url == "http://127.0.0.1:8000"
    assert "127.0.0.1" in cfg.staging_allowed_hosts


@pytest.mark.asyncio
async def test_connectivity_check_unreachable_endpoint():
    cfg = ExternalStagingConfig(
        zerophish_env="staging",
        staging_base_url="http://127.0.0.1:19999",  # Nothing listening
        staging_allowed_hosts=["127.0.0.1"],
        connect_timeout_sec=0.1,
        request_timeout_sec=0.5,
    )
    res = await ExternalStagingRunner.check_connectivity(cfg)
    assert res["reachable"] is False
    assert "error_type" in res


@pytest.mark.asyncio
async def test_runner_error_budget_and_runtime_deadline():
    cfg = ExternalStagingConfig(
        zerophish_env="staging",
        staging_base_url="http://127.0.0.1:19999",  # Nothing listening
        staging_allowed_hosts=["127.0.0.1"],
        connect_timeout_sec=0.01,
        read_timeout_sec=0.01,
        request_timeout_sec=0.05,
        max_retries=1,
        max_errors=2,  # Stop after 2 failures
        max_runtime_sec=2.0,
    )
    runner = ExternalStagingRunner(config=cfg)
    res = await runner.execute_workload(count=10, rate_rps=100.0)

    assert res["status"] in ("FAILED_ERROR_BUDGET_EXCEEDED", "TIMEOUT")
    assert runner.accounting["HTTP_REQUESTS_FAILED"] >= 2
    assert len(runner.recorded_errors) >= 2


@pytest.mark.asyncio
async def test_runner_successful_execution_and_artifacts(monkeypatch):
    import httpx

    async def mock_post(self, url, *args, **kwargs):
        return httpx.Response(200, json={"status": "ok", "verdict": "SAFE"})

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    cfg = ExternalStagingConfig(
        zerophish_env="staging",
        staging_base_url="http://127.0.0.1:8000",
        staging_allowed_hosts=["127.0.0.1"],
        connect_timeout_sec=1.0,
        request_timeout_sec=2.0,
        max_runtime_sec=5.0,
        progress_every=5,
    )
    runner = ExternalStagingRunner(config=cfg)
    res = await runner.execute_workload(count=10, rate_rps=100.0)

    assert res["status"] == "COMPLETE"
    assert res["accounting"]["HTTP_REQUESTS_SUCCESSFUL"] == 10
    assert res["accounting"]["SHADOW_OBSERVATIONS_RECORDED"] == 1  # 10% of 10

    staging_dir = (
        Path(__file__).resolve().parents[1] / "ml" / "benchmarks" / "shadow" / "staging_external"
    )
    assert (staging_dir / "run_manifest.json").exists()
    assert (staging_dir / "request_accounting.json").exists()
    assert (staging_dir / "network_report.json").exists()
    assert (staging_dir / "progress.json").exists()
    assert (staging_dir / "errors.json").exists()
    assert (staging_dir / "stage_distribution.json").exists()
    assert (staging_dir / "invocation_rates.json").exists()
    assert (staging_dir / "latency_report.json").exists()
    assert (staging_dir / "disagreement_report.json").exists()
    assert (staging_dir / "resource_report.json").exists()
    assert (staging_dir / "final_report.md").exists()


@pytest.mark.asyncio
async def test_connectivity_check_success(monkeypatch):
    import httpx

    async def mock_post(self, url, *args, **kwargs):
        return httpx.Response(200, json={"status": "healthy"})

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    cfg = ExternalStagingConfig(
        zerophish_env="staging",
        staging_base_url="http://127.0.0.1:8000",
        staging_allowed_hosts=["127.0.0.1"],
        api_token="test-token-123",
    )
    res = await ExternalStagingRunner.check_connectivity(cfg)
    assert res["reachable"] is True
    assert res["status_code"] == 200


def test_no_asgitransport_or_testclient_in_external_runner():
    client_file = Path(__file__).resolve().parents[1] / "ml" / "data" / "external_staging_client.py"
    content = client_file.read_text(encoding="utf-8")
    assert "import ASGITransport" not in content
    assert "ASGITransport(" not in content
    assert "import TestClient" not in content
    assert "TestClient(" not in content
    assert "from main import app" not in content
    assert "import app" not in content
