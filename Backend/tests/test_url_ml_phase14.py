"""
Unit tests for Phase 14 Staging Environment Topology, Health/Readiness Endpoints,
and Environment Isolation.
"""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from gateway import app


@pytest.mark.asyncio
async def test_staging_health_liveness_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "environment" in data


@pytest.mark.asyncio
async def test_staging_readiness_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert "dependencies" in data
        assert data["dependencies"]["database"] == "ready" or "repository" in data["dependencies"]


def test_staging_deployment_artifacts_exist():
    root = Path(__file__).resolve().parents[2]
    assert (root / "docker-compose.staging.yml").exists()
    assert (root / "Backend" / "Dockerfile.staging").exists()
    assert (root / ".env.staging.example").exists()
    assert (root / "scripts" / "staging-up.ps1").exists()
    assert (root / "scripts" / "staging-down.ps1").exists()
    assert (root / "scripts" / "staging-health.ps1").exists()
    assert (root / "docs" / "staging" / "architecture.md").exists()
    assert (root / "docs" / "staging" / "deployment.md").exists()
    assert (root / "docs" / "staging" / "configuration.md").exists()
    assert (root / "docs" / "staging" / "operations.md").exists()
    assert (root / "docs" / "staging" / "troubleshooting.md").exists()
