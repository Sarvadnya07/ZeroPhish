"""
Unit tests for tier_2/whois_client.py.
Covers cache layer, library lookups, API fallbacks, retry logic, and singleton lifecycle.
"""
from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from tier_2.whois_client import WhoisClient, get_whois_client


@pytest.fixture
def mock_cache():
    cache = MagicMock()
    cache.get = AsyncMock(return_value=None)
    cache.setex = AsyncMock()
    return cache


@pytest.mark.asyncio
async def test_whois_cache_hit(mock_cache):
    """Test fast return when domain is found in cache."""
    mock_cache.get.return_value = json.dumps({"age": 365, "cached_at": "2026-01-01T00:00:00Z"})
    client = WhoisClient(cache_client=mock_cache)

    age, source = await client.get_domain_age("example.com")
    assert age == 365
    assert source == "cache"
    await client.close()


@pytest.mark.asyncio
async def test_whois_library_success(mock_cache):
    """Test successful lookup via python-whois library."""
    client = WhoisClient(cache_client=mock_cache)

    mock_record = MagicMock()
    mock_record.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)

    with patch("whois.whois", return_value=mock_record):
        age, source = await client.get_domain_age("google.com")
        assert age is not None
        assert age > 1000
        assert source == "library"
        mock_cache.setex.assert_called_once()

    await client.close()


@pytest.mark.asyncio
async def test_whois_library_list_creation_date():
    """Test python-whois returning a list of creation dates."""
    client = WhoisClient()
    mock_record = MagicMock()
    mock_record.creation_date = [datetime(2022, 1, 1), datetime(2023, 1, 1)]

    with patch("whois.whois", return_value=mock_record):
        age, source = await client.get_domain_age("listdomain.com")
        assert age is not None
        assert age > 500
        assert source == "library"

    await client.close()


@pytest.mark.asyncio
async def test_whois_api_whoisxml_fallback(mock_cache):
    """Test fallback to WhoisXML API when library fails."""
    client = WhoisClient(api_provider="whoisxml", api_key="dummy-key", cache_client=mock_cache)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "WhoisRecord": {"createdDate": "2021-06-15T12:00:00Z"}
    }

    with patch("whois.whois", side_effect=Exception("WHOIS server blocked")):
        with patch.object(client.http_client, "get", new_callable=AsyncMock, return_value=mock_resp):
            age, source = await client.get_domain_age("whoisxml-test.com")
            assert age is not None
            assert age > 500
            assert source == "api"

    await client.close()


@pytest.mark.asyncio
async def test_whois_api_whoisapi_fallback():
    """Test WhoisAPI.com provider fallback."""
    client = WhoisClient(api_provider="whoisapi", api_key="dummy-key")

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"created_date": "2023-01-01T00:00:00+00:00"}

    with patch("whois.whois", side_effect=Exception("WHOIS library error")):
        with patch.object(client.http_client, "get", new_callable=AsyncMock, return_value=mock_resp):
            age, source = await client.get_domain_age("whoisapi-test.com")
            assert age is not None
            assert age > 200
            assert source == "api"

    await client.close()


@pytest.mark.asyncio
async def test_whois_all_methods_fail(mock_cache):
    """Test unknown source when library and API both fail."""
    client = WhoisClient(api_provider="unknown_provider", api_key="dummy-key", cache_client=mock_cache)

    with patch("whois.whois", side_effect=Exception("Fail")):
        age, source = await client.get_domain_age("nonexistent-domain.xyz")
        assert age is None
        assert source == "unknown"

    await client.close()


@pytest.mark.asyncio
async def test_whois_cache_exceptions_dont_crash():
    """Test that cache read/write errors are handled gracefully without raising."""
    faulty_cache = MagicMock()
    faulty_cache.get = AsyncMock(side_effect=RuntimeError("Redis connection lost"))
    faulty_cache.setex = AsyncMock(side_effect=RuntimeError("Redis write failed"))

    client = WhoisClient(cache_client=faulty_cache)
    mock_record = MagicMock()
    mock_record.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)

    with patch("whois.whois", return_value=mock_record):
        age, source = await client.get_domain_age("resilient.com")
        assert age is not None
        assert source == "library"

    await client.close()


@pytest.mark.asyncio
async def test_get_whois_client_singleton():
    """Test global singleton creator for WhoisClient."""
    import tier_2.whois_client as whois_mod
    whois_mod._whois_client_instance = None

    c1 = await get_whois_client()
    c2 = await get_whois_client()
    assert c1 is c2
    await c1.close()
    whois_mod._whois_client_instance = None
