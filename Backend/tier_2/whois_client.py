"""
WHOIS & RDAP Client with Multi-Provider Fallback and Resilient Caching.

Provides reliable domain age lookups with cascading fallback strategies:
1. Cache layer (Redis or bounded LRU in-memory with positive & negative TTL)
2. Local python-whois library (bounded execution with strict timeout)
3. ICANN RDAP client over HTTPS (fast, non-blocking REST, no port 43 socket, SSRF protected)
4. Paid WHOIS API (WhoisXML / WhoisAPI with retries)

All operations are async, with a synchronous wrapper for convenience.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import hashlib
import json
import logging
import os
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx
import whois
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)

# SSRF helper import with robust fallbacks
try:
    from security.middleware import is_safe_url
except ImportError:
    try:
        from Backend.security.middleware import is_safe_url
    except ImportError:
        def is_safe_url(url: str, allow_http: bool = False) -> bool:
            return True

# ---------- Configuration ----------
DEFAULT_API_PROVIDER = os.getenv("WHOIS_API_PROVIDER", "whoisxml")
DEFAULT_API_KEY = os.getenv("WHOIS_API_KEY")
DEFAULT_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL", "86400"))  # 24 hours positive
DEFAULT_NEGATIVE_CACHE_TTL = int(os.getenv("WHOIS_NEGATIVE_CACHE_TTL", "300"))  # 5 minutes negative
DEFAULT_HTTP_TIMEOUT = float(os.getenv("WHOIS_HTTP_TIMEOUT", "10.0"))
DEFAULT_RDAP_TIMEOUT = float(os.getenv("WHOIS_RDAP_TIMEOUT", "2.0"))
DEFAULT_LIBRARY_TIMEOUT = float(os.getenv("WHOIS_LIBRARY_TIMEOUT", "2.0"))
DEFAULT_RETRY_ATTEMPTS = int(os.getenv("WHOIS_RETRY_ATTEMPTS", "3"))
DEFAULT_RETRY_WAIT_MIN = float(os.getenv("WHOIS_RETRY_WAIT_MIN", "1.0"))
DEFAULT_RETRY_WAIT_MAX = float(os.getenv("WHOIS_RETRY_WAIT_MAX", "5.0"))
DEFAULT_ENABLE_CACHE = os.getenv("WHOIS_ENABLE_CACHE", "true").lower() == "true"
DEFAULT_ENABLE_RDAP = os.getenv("WHOIS_ENABLE_RDAP", "true").lower() == "true"
MAX_IN_MEMORY_CACHE_SIZE = int(os.getenv("WHOIS_MAX_CACHE_SIZE", "1000"))

# RDAP & API endpoints
RDAP_BOOTSTRAP_URL = os.getenv("RDAP_BOOTSTRAP_URL", "https://rdap.org/domain/")
API_ENDPOINTS = {
    "whoisxml": "https://www.whoisxmlapi.com/whoisserver/WhoisService",
    "whoisapi": "https://www.whoisapi.com/api/v1",
}


class WhoisClient:
    """
    Unified WHOIS & RDAP client with fallback cascade, bounded LRU caching,
    and SSRF protections.
    """

    def __init__(
        self,
        api_provider: str = DEFAULT_API_PROVIDER,
        api_key: Optional[str] = None,
        cache_client: Optional[Any] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        negative_cache_ttl: int = DEFAULT_NEGATIVE_CACHE_TTL,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
        rdap_timeout: float = DEFAULT_RDAP_TIMEOUT,
        library_timeout: float = DEFAULT_LIBRARY_TIMEOUT,
        enable_cache: bool = DEFAULT_ENABLE_CACHE,
        enable_rdap: bool = DEFAULT_ENABLE_RDAP,
        max_cache_size: int = MAX_IN_MEMORY_CACHE_SIZE,
    ) -> None:
        self.api_provider = api_provider
        self.api_key = api_key or DEFAULT_API_KEY
        self.cache_client = cache_client
        self.cache_ttl = cache_ttl
        self.negative_cache_ttl = negative_cache_ttl
        self.http_timeout = http_timeout
        self.rdap_timeout = rdap_timeout
        self.library_timeout = library_timeout
        self.enable_cache = enable_cache
        self.enable_rdap = enable_rdap
        self.max_cache_size = max_cache_size

        # Bounded LRU in-memory cache: key -> (age_or_none, expiry_timestamp, status, source)
        self._in_memory_cache: OrderedDict[str, Tuple[Optional[int], float, str, str]] = OrderedDict()

        # HTTP client (lazy init)
        self._http_client: Optional[httpx.AsyncClient] = None

        logger.info(
            "WhoisClient initialized: provider=%s, cache=%s (ttl=%ds, neg_ttl=%ds), rdap=%s",
            self.api_provider,
            "enabled" if self.enable_cache else "disabled",
            self.cache_ttl,
            self.negative_cache_ttl,
            "enabled" if self.enable_rdap else "disabled",
        )

    @property
    def http_client(self) -> httpx.AsyncClient:
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

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Clean and normalize domain string for lookups and cache keys."""
        if not domain:
            return ""
        norm = domain.strip().lower()
        if "@" in norm:
            norm = norm.split("@")[-1]
        norm = norm.strip("<>[]{}'\"")
        norm = norm.rstrip(".")
        return norm

    async def get_domain_age(self, domain: str) -> Tuple[Optional[int], str]:
        """
        Get domain age in days with fallback cascade.

        Returns:
            Tuple of (age_in_days, source)
            - age_in_days: None if unknown/failed, otherwise integer days since creation
            - source: "cache" | "library" | "rdap" | "api" | "unknown"
        """
        norm_domain = self.normalize_domain(domain)
        if not norm_domain:
            logger.warning("Empty domain provided")
            return None, "unknown"

        # 1. Check cache (positive and negative)
        if self.enable_cache:
            cached_age, cached_source = await self._get_from_cache(norm_domain)
            if cached_source is not None:
                return cached_age, cached_source

        # 2. Local python-whois library (with bounded execution timeout)
        age = await self._get_from_library(norm_domain)
        if age is not None:
            await self._save_to_cache(norm_domain, age, status="VERIFIED", source="library")
            return age, "library"

        # 3. External paid WHOIS API (if explicitly configured by user/caller)
        if self.api_key:
            try:
                age = await self._get_from_api(norm_domain)
                if age is not None:
                    await self._save_to_cache(norm_domain, age, status="VERIFIED", source="api")
                    return age, "api"
            except Exception as e:
                logger.warning("All API attempts failed for %s: %s", norm_domain, e)
        else:
            logger.debug("No API key configured, skipping API lookup")

        # 4. RDAP client over HTTPS (fast, non-blocking RFC 7480-7484)
        if self.enable_rdap:
            age = await self._get_from_rdap(norm_domain)
            if age is not None:
                await self._save_to_cache(norm_domain, age, status="VERIFIED", source="rdap")
                return age, "rdap"

        # 5. All lookups failed or domain unlisted: save negative cache entry
        if self.enable_cache:
            await self._save_negative_to_cache(norm_domain, status="LOOKUP_FAILED")

        logger.warning("Could not determine age for domain: %s", norm_domain)
        return None, "unknown"

    async def get_domain_intel(self, domain: str) -> Tuple[Optional[int], str, str]:
        """
        Enhanced domain intelligence lookup returning:
        (age_days, status_label, source)

        status_label is one of:
        - "VERIFIED_NEW" (age < 30 days)
        - "VERIFIED_SUSPICIOUS" (30 <= age < 365 days)
        - "VERIFIED_ESTABLISHED" (age >= 365 days)
        - "UNKNOWN" (registration unlisted or unverified)
        - "LOOKUP_FAILED" (network timeout, provider error, unreachable)
        """
        age, source = await self.get_domain_age(domain)
        if age is not None:
            if age < 30:
                status_label = "VERIFIED_NEW"
            elif age < 365:
                status_label = "VERIFIED_SUSPICIOUS"
            else:
                status_label = "VERIFIED_ESTABLISHED"
        else:
            status_label = "LOOKUP_FAILED" if source in ("unknown", "cache:negative") else "UNKNOWN"

        return age, status_label, source

    async def _get_from_rdap(self, domain: str) -> Optional[int]:
        """
        Query ICANN RDAP over HTTPS with SSRF protection and redirect validation.
        """
        rdap_url = f"{RDAP_BOOTSTRAP_URL}{urllib.parse.quote(domain)}"
        if not is_safe_url(rdap_url, allow_http=False):
            logger.warning("SSRF blocked initial RDAP URL: %s", rdap_url)
            return None

        try:
            client = self.http_client
            curr_url = rdap_url
            for _ in range(3):
                resp = await client.get(
                    curr_url,
                    timeout=httpx.Timeout(self.rdap_timeout),
                    follow_redirects=False,
                    headers={"Accept": "application/rdap+json, application/json"},
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        break
                    next_url = urllib.parse.urljoin(curr_url, loc)
                    if not is_safe_url(next_url, allow_http=False):
                        logger.warning("SSRF blocked RDAP redirect destination: %s", next_url)
                        return None
                    curr_url = next_url
                elif resp.status_code == 200:
                    data = resp.json()
                    for ev in data.get("events", []):
                        action = ev.get("eventAction", "").lower()
                        if action in ("registration", "created", "last changed"):
                            date_str = ev.get("eventDate")
                            if date_str and action in ("registration", "created"):
                                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=timezone.utc)
                                age = (datetime.now(timezone.utc) - dt).days
                                logger.debug("RDAP lookup successful for %s: %d days", domain, age)
                                return max(0, age)
                    return None
                elif resp.status_code == 404:
                    logger.debug("RDAP 404 domain not found: %s", domain)
                    return None
                else:
                    break
        except (httpx.TimeoutException, httpx.RequestError, ValueError, TypeError) as e:
            logger.debug("RDAP lookup error for %s: %s", domain, e)
            return None
        return None

    async def _get_from_library(self, domain: str) -> Optional[int]:
        """Get domain age using python-whois library bounded by timeout."""
        try:
            logger.debug("Trying local WHOIS library for: %s", domain)

            def _whois_lookup() -> Optional[int]:
                w = whois.whois(domain)
                creation_date = getattr(w, "creation_date", None)
                if creation_date is None:
                    return None
                if isinstance(creation_date, list):
                    creation_date = creation_date[0] if creation_date else None
                if creation_date is None:
                    return None
                if not isinstance(creation_date, datetime):
                    try:
                        creation_date = datetime.fromisoformat(str(creation_date))
                    except (ValueError, TypeError):
                        return None
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age = (now - creation_date).days
                return max(0, age)

            age = await asyncio.wait_for(
                asyncio.to_thread(_whois_lookup),
                timeout=self.library_timeout,
            )
            if age is not None:
                logger.debug("Library lookup successful: %s = %d days", domain, age)
            return age
        except (whois.parser.PywhoisError, asyncio.TimeoutError, TimeoutError) as e:
            logger.debug("WHOIS library error or timeout for %s: %s", domain, e)
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
        """Get domain age using WHOIS API with retry logic."""
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
        client = self.http_client
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
            if created_date.tzinfo is None:
                created_date = created_date.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created_date).days
            return max(0, age)
        except (ValueError, TypeError) as e:
            logger.warning("Failed to parse creation date for %s: %s", domain, e)
            return None

    async def _query_whoisapi(self, domain: str) -> Optional[int]:
        """Query WhoisAPI.com."""
        client = self.http_client
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
            if created_date.tzinfo is None:
                created_date = created_date.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created_date).days
            return max(0, age)
        except (ValueError, TypeError) as e:
            logger.warning("Failed to parse creation date for %s: %s", domain, e)
            return None

    async def _get_from_cache(self, domain: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Get domain age from cache.
        Returns:
            (age, source) if cache hit
            (None, None) if cache miss
        """
        if not self.enable_cache:
            return None, None

        key = self._cache_key(domain)

        # 1. Check Redis first
        if self.cache_client is not None:
            try:
                cached_data = await self.cache_client.get(key)
                if cached_data:
                    data = json.loads(cached_data)
                    age = data.get("age")
                    status = data.get("status", "VERIFIED")
                    if status == "LOOKUP_FAILED" and age is None:
                        logger.debug("Redis negative cache hit for: %s", domain)
                        return None, "cache:negative"
                    logger.debug("Redis cache hit for domain: %s = %s days", domain, age)
                    return age, "cache"
            except Exception as e:
                logger.debug("Redis cache read error for %s: %s", domain, e)

        # 2. Check in-memory LRU cache
        if key in self._in_memory_cache:
            age, expiry, status, source = self._in_memory_cache[key]
            if expiry > time.time():
                # Move to end (most recently accessed)
                self._in_memory_cache.move_to_end(key)
                if status == "LOOKUP_FAILED" and age is None:
                    logger.debug("In-memory negative cache hit for: %s", domain)
                    return None, "cache:negative"
                logger.debug("In-memory cache hit for domain: %s = %s days", domain, age)
                return age, "cache"
            else:
                del self._in_memory_cache[key]

        return None, None

    async def _save_to_cache(self, domain: str, age: int, status: str = "VERIFIED", source: str = "lookup") -> None:
        """Save positive domain age to cache (Redis and in-memory)."""
        if not self.enable_cache:
            return

        key = self._cache_key(domain)
        data = json.dumps({
            "age": age,
            "status": status,
            "source": source,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        })

        if self.cache_client is not None:
            try:
                await self.cache_client.setex(key, self.cache_ttl, data)
                logger.debug("Cached domain age in Redis: %s = %d days", domain, age)
            except Exception as e:
                logger.debug("Redis cache write error for %s: %s", domain, e)

        # Save to bounded in-memory LRU
        if key in self._in_memory_cache:
            self._in_memory_cache.move_to_end(key)
        self._in_memory_cache[key] = (age, time.time() + self.cache_ttl, status, source)
        if len(self._in_memory_cache) > self.max_cache_size:
            self._in_memory_cache.popitem(last=False)

    async def _save_negative_to_cache(self, domain: str, status: str = "LOOKUP_FAILED") -> None:
        """Save negative result to cache with shorter TTL to prevent repeated network hangs."""
        if not self.enable_cache:
            return

        key = self._cache_key(domain)
        data = json.dumps({
            "age": None,
            "status": status,
            "source": "negative_cache",
            "cached_at": datetime.now(timezone.utc).isoformat(),
        })

        if self.cache_client is not None:
            try:
                await self.cache_client.setex(key, self.negative_cache_ttl, data)
                logger.debug("Cached negative domain lookup in Redis: %s", domain)
            except Exception as e:
                logger.debug("Redis negative cache write error for %s: %s", domain, e)

        # Save to in-memory LRU
        if key in self._in_memory_cache:
            self._in_memory_cache.move_to_end(key)
        self._in_memory_cache[key] = (None, time.time() + self.negative_cache_ttl, status, "negative_cache")
        if len(self._in_memory_cache) > self.max_cache_size:
            self._in_memory_cache.popitem(last=False)

    def _cache_key(self, domain: str) -> str:
        """Generate deterministic collision-resistant cache key."""
        clean = self.normalize_domain(domain)
        domain_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()
        return f"whois:domain:{domain_hash}"

    async def health_check(self) -> Dict[str, Any]:
        """Check health of the WHOIS client and its dependencies."""
        status = {
            "service": "whois",
            "api_provider": self.api_provider,
            "api_configured": bool(self.api_key),
            "cache_enabled": self.enable_cache,
            "rdap_enabled": self.enable_rdap,
            "redis_available": self.cache_client is not None,
            "cache_ttl": self.cache_ttl,
            "negative_cache_ttl": self.negative_cache_ttl,
            "in_memory_cached_domains": len(self._in_memory_cache),
            "http_client_connected": self._http_client is not None,
        }

        try:
            age, source = await self.get_domain_age("google.com")
            status["test_lookup_success"] = age is not None
            status["test_lookup_source"] = source
        except Exception as e:
            status["test_lookup_success"] = False
            status["test_lookup_error"] = str(e)

        return status


# ---------- Synchronous Wrapper ----------
def get_domain_age_sync(domain: str) -> Tuple[Optional[int], str]:
    """Synchronous wrapper for get_domain_age."""
    async def _run():
        client = WhoisClient()
        try:
            return await client.get_domain_age(domain)
        finally:
            await client.close()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, _run())
            return future.result()


# ---------- Global Singleton with Lock ----------
_whois_client_instance: Optional[WhoisClient] = None
_whois_client_lock = asyncio.Lock()


async def get_whois_client(
    cache_client: Optional[Any] = None,
    api_key: Optional[str] = None,
    api_provider: Optional[str] = None,
) -> WhoisClient:
    """Get or create the global WHOIS client instance with concurrency protection."""
    global _whois_client_instance

    if _whois_client_instance is None:
        async with _whois_client_lock:
            if _whois_client_instance is None:
                _whois_client_instance = WhoisClient(
                    api_provider=api_provider or DEFAULT_API_PROVIDER,
                    api_key=api_key or DEFAULT_API_KEY,
                    cache_client=cache_client,
                    cache_ttl=DEFAULT_CACHE_TTL,
                    negative_cache_ttl=DEFAULT_NEGATIVE_CACHE_TTL,
                    http_timeout=DEFAULT_HTTP_TIMEOUT,
                    enable_cache=DEFAULT_ENABLE_CACHE,
                    enable_rdap=DEFAULT_ENABLE_RDAP,
                )
                logger.info("Global WHOIS/RDAP client initialised.")

    return _whois_client_instance