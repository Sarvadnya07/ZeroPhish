"""
WHOIS Client with Multi-Provider Fallback

Provides reliable domain age lookups with cascading fallback strategies:
1. Local python-whois library (fast, free, but can fail)
2. WHOIS API (reliable, requires API key, rate limited)
3. Redis cache (fastest, for previously queried domains)

All operations are async, with a synchronous wrapper for convenience.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx
import whois
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)

# ---------- Configuration ----------
DEFAULT_API_PROVIDER = os.getenv("WHOIS_API_PROVIDER", "whoisxml")
DEFAULT_API_KEY = os.getenv("WHOIS_API_KEY")
DEFAULT_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL", "86400"))  # 24 hours
DEFAULT_HTTP_TIMEOUT = float(os.getenv("WHOIS_HTTP_TIMEOUT", "10.0"))
DEFAULT_RETRY_ATTEMPTS = int(os.getenv("WHOIS_RETRY_ATTEMPTS", "3"))
DEFAULT_RETRY_WAIT_MIN = float(os.getenv("WHOIS_RETRY_WAIT_MIN", "1.0"))
DEFAULT_RETRY_WAIT_MAX = float(os.getenv("WHOIS_RETRY_WAIT_MAX", "5.0"))
DEFAULT_ENABLE_CACHE = os.getenv("WHOIS_ENABLE_CACHE", "true").lower() == "true"

# API endpoints
API_ENDPOINTS = {
    "whoisxml": "https://www.whoisxmlapi.com/whoisserver/WhoisService",
    "whoisapi": "https://www.whoisapi.com/api/v1",
}


class WhoisClient:
    """
    Unified WHOIS client with fallback cascade and caching.

    Usage:
        client = WhoisClient()
        age_days, source = await client.get_domain_age("example.com")
        # age_days: int or None, source: "cache" | "library" | "api" | "unknown"

    Attributes:
        api_provider: WHOIS API provider ("whoisxml" or "whoisapi").
        api_key: API key (optional, read from env if not provided).
        cache_client: Redis client or any async cache with get/set methods.
        cache_ttl: TTL for cached entries in seconds.
        http_client: httpx.AsyncClient for API calls.
        enable_cache: Whether to use caching.
        _in_memory_cache: Fallback in‑memory cache if Redis is not available.
    """

    def __init__(
        self,
        api_provider: str = DEFAULT_API_PROVIDER,
        api_key: Optional[str] = None,
        cache_client: Optional[Any] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
        enable_cache: bool = DEFAULT_ENABLE_CACHE,
    ) -> None:
        self.api_provider = api_provider
        self.api_key = api_key or DEFAULT_API_KEY
        self.cache_client = cache_client
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self.http_timeout = http_timeout

        # In‑memory fallback cache
        self._in_memory_cache: Dict[str, Tuple[int, float]] = {}  # key -> (age, expiry_time)

        # HTTP client (lazy init)
        self._http_client: Optional[httpx.AsyncClient] = None

        logger.info(
            "WhoisClient initialized: provider=%s, cache=%s, ttl=%ds",
            self.api_provider,
            "enabled" if self.enable_cache else "disabled",
            self.cache_ttl,
        )

    @property
    async def http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client (lazy)."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.http_timeout),
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
            )
            logger.debug("HTTP client created")
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
            logger.debug("HTTP client closed")

    async def __aenter__(self) -> WhoisClient:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def get_domain_age(self, domain: str) -> Tuple[Optional[int], str]:
        """
        Get domain age in days with fallback cascade.

        Returns:
            Tuple of (age_in_days, source)
            - age_in_days: None if unknown, otherwise days since creation
            - source: "cache", "library", "api", or "unknown"
        """
        if not domain or not domain.strip():
            logger.warning("Empty domain provided")
            return None, "unknown"

        domain = domain.strip().lower()

        # 1. Check cache
        if self.enable_cache:
            cached_age = await self._get_from_cache(domain)
            if cached_age is not None:
                return cached_age, "cache"

        # 2. Local library
        age = await self._get_from_library(domain)
        if age is not None:
            await self._save_to_cache(domain, age)
            return age, "library"

        # 3. API (if API key is configured)
        if self.api_key:
            try:
                age = await self._get_from_api(domain)
                if age is not None:
                    await self._save_to_cache(domain, age)
                    return age, "api"
            except Exception as e:
                logger.warning("All API attempts failed for %s: %s", domain, e)
        else:
            logger.debug("No API key configured, skipping API lookup")

        # 4. All methods failed
        logger.warning("Could not determine age for domain: %s", domain)
        return None, "unknown"

    async def _get_from_library(self, domain: str) -> Optional[int]:
        """Get domain age using python-whois library."""
        try:
            logger.debug("Trying local WHOIS library for: %s", domain)

            def _whois_lookup() -> Optional[int]:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if creation_date is None:
                    return None
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date is None:
                    return None
                # Normalise to timezone‑aware UTC
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age = (now - creation_date).days
                return age

            age = await asyncio.to_thread(_whois_lookup)
            if age is not None:
                logger.debug("Library lookup successful: %s = %d days", domain, age)
            return age
        except whois.parser.PywhoisError as e:
            logger.debug("WHOIS library error for %s: %s", domain, e)
            return None
        except Exception as e:
            logger.debug("WHOIS library lookup failed for %s: %s", domain, e)
            return None

    @retry(
        stop=stop_after_attempt(DEFAULT_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=DEFAULT_RETRY_WAIT_MIN, max=DEFAULT_RETRY_WAIT_MAX),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _get_from_api(self, domain: str) -> Optional[int]:
        """
        Get domain age using WHOIS API with retry logic.

        Raises:
            httpx.HTTPStatusError: On HTTP errors (will be retried).
            httpx.TimeoutException: On timeout (will be retried).
            ValueError: On malformed response.
        """
        logger.debug("Trying WHOIS API (%s) for: %s", self.api_provider, domain)

        if self.api_provider == "whoisxml":
            age = await self._query_whoisxml(domain)
        elif self.api_provider == "whoisapi":
            age = await self._query_whoisapi(domain)
        else:
            raise ValueError(f"Unknown API provider: {self.api_provider}")

        if age is not None:
            logger.debug("API lookup successful: %s = %d days", domain, age)
        return age

    async def _query_whoisxml(self, domain: str) -> Optional[int]:
        """Query WhoisXML API."""
        client = await self.http_client
        url = API_ENDPOINTS["whoisxml"]
        params = {"apiKey": self.api_key, "domainName": domain, "outputFormat": "JSON"}

        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        created_date_str = data.get("WhoisRecord", {}).get("createdDate")
        if not created_date_str:
            return None

        try:
            created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - created_date).days
            return age
        except (ValueError, TypeError) as e:
            logger.warning("Failed to parse creation date for %s: %s", domain, e)
            return None

    async def _query_whoisapi(self, domain: str) -> Optional[int]:
        """Query WhoisAPI.com."""
        client = await self.http_client
        url = API_ENDPOINTS["whoisapi"]
        params = {"apiKey": self.api_key, "domainName": domain}

        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        created_date_str = data.get("created_date")
        if not created_date_str:
            return None

        try:
            created_date = datetime.fromisoformat(created_date_str)
            age = (datetime.now(timezone.utc) - created_date).days
            return age
        except (ValueError, TypeError) as e:
            logger.warning("Failed to parse creation date for %s: %s", domain, e)
            return None

    async def _get_from_cache(self, domain: str) -> Optional[int]:
        """Get domain age from cache (Redis or in‑memory)."""
        if not self.enable_cache:
            return None

        key = self._cache_key(domain)

        # Try Redis first
        if self.cache_client is not None:
            try:
                cached_data = await self.cache_client.get(key)
                if cached_data:
                    data = json.loads(cached_data)
                    age = data.get("age")
                    logger.debug("Redis cache hit for domain: %s = %d days", domain, age)
                    return age
            except Exception as e:
                logger.debug("Redis cache read error for %s: %s", domain, e)

        # Fallback to in‑memory
        if key in self._in_memory_cache:
            age, expiry = self._in_memory_cache[key]
            if expiry > time.time():
                logger.debug("In‑memory cache hit for domain: %s = %d days", domain, age)
                return age
            else:
                del self._in_memory_cache[key]

        return None

    async def _save_to_cache(self, domain: str, age: int) -> None:
        """Save domain age to cache (Redis and in‑memory)."""
        if not self.enable_cache:
            return

        key = self._cache_key(domain)
        data = json.dumps({"age": age, "cached_at": datetime.now(timezone.utc).isoformat()})

        # Save to Redis if available
        if self.cache_client is not None:
            try:
                await self.cache_client.setex(key, self.cache_ttl, data)
                logger.debug("Cached domain age in Redis: %s = %d days", domain, age)
            except Exception as e:
                logger.debug("Redis cache write error for %s: %s", domain, e)

        # Save to in‑memory fallback
        self._in_memory_cache[key] = (age, time.time() + self.cache_ttl)

    def _cache_key(self, domain: str) -> str:
        """Generate cache key for domain."""
        domain_hash = hashlib.md5(domain.lower().encode()).hexdigest()
        return f"whois:domain:{domain_hash}"

    async def health_check(self) -> Dict[str, Any]:
        """Check health of the WHOIS client and its dependencies."""
        status = {
            "service": "whois",
            "api_provider": self.api_provider,
            "api_configured": bool(self.api_key),
            "cache_enabled": self.enable_cache,
            "redis_available": self.cache_client is not None,
            "cache_ttl": self.cache_ttl,
            "http_client_connected": self._http_client is not None,
        }

        # Test a simple lookup (optional, but could be expensive)
        # For health, we just check that the client can be initialised.
        try:
            # Test domain (google.com should exist)
            age, source = await self.get_domain_age("google.com")
            status["test_lookup_success"] = age is not None
            status["test_lookup_source"] = source
        except Exception as e:
            status["test_lookup_success"] = False
            status["test_lookup_error"] = str(e)

        return status


# ---------- Synchronous Wrapper ----------
def get_domain_age_sync(domain: str) -> Tuple[Optional[int], str]:
    """
    Synchronous wrapper for get_domain_age.

    Uses a thread‑pool executor to run the async method.

    Usage:
        age, source = get_domain_age_sync("example.com")
    """
    async def _run():
        client = WhoisClient()
        return await client.get_domain_age(domain)

    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop, create a new one
        return asyncio.run(_run())
    else:
        # Already in a loop, run in thread (not recommended, but works)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, _run())
            return future.result()


# ---------- Global Instance ----------
_whois_client_instance: Optional[WhoisClient] = None


async def get_whois_client(
    cache_client: Optional[Any] = None,
    api_key: Optional[str] = None,
    api_provider: Optional[str] = None,
) -> WhoisClient:
    """Get or create the global WHOIS client instance."""
    global _whois_client_instance

    if _whois_client_instance is None:
        _whois_client_instance = WhoisClient(
            api_provider=api_provider or DEFAULT_API_PROVIDER,
            api_key=api_key or DEFAULT_API_KEY,
            cache_client=cache_client,
            cache_ttl=DEFAULT_CACHE_TTL,
            http_timeout=DEFAULT_HTTP_TIMEOUT,
            enable_cache=DEFAULT_ENABLE_CACHE,
        )
        logger.info("Global WHOIS client initialised.")

    return _whois_client_instance