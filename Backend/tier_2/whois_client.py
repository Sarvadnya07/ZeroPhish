"""
WHOIS Client with Multi-Provider Fallback
Provides reliable domain age lookups with cascading fallback strategies
"""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

import httpx
import whois
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class WhoisClient:
    """
    Unified WHOIS client with fallback cascade:
    1. Local python-whois library (fast, free, but can fail)
    2. WHOIS API (reliable, requires API key, rate limited)
    3. Redis cache (fastest, for previously queried domains)
    """

    def __init__(
        self,
        api_provider: str = "whoisxml",
        api_key: Optional[str] = None,
        cache_client=None,
        cache_ttl: int = 86400,  # 24 hours
    ):
        self.api_provider = api_provider
        self.api_key = api_key or os.getenv("WHOIS_API_KEY")
        self.cache_client = cache_client
        self.cache_ttl = cache_ttl
        self.http_client = httpx.AsyncClient(timeout=10.0)

        # API endpoints
        self.api_endpoints = {
            "whoisxml": "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            "whoisapi": "https://www.whoisapi.com/api/v1",
            "ipapi": "http://ip-api.com/json/{domain}",
        }

    async def get_domain_age(self, domain: str) -> Tuple[int, str]:
        """
        Get domain age in days with fallback cascade.

        Returns:
            Tuple of (age_in_days, source)
            - age_in_days: 0 if unknown, otherwise days since creation
            - source: "library", "api", "cache", or "unknown"
        """
        # Step 1: Check cache first (fastest)
        cached_age = await self._get_from_cache(domain)
        if cached_age is not None:
            return cached_age, "cache"

        # Step 2: Try local WHOIS library
        age = await self._get_from_library(domain)
        if age is not None:
            await self._save_to_cache(domain, age)
            return age, "library"

        # Step 3: Try WHOIS API (if configured)
        if self.api_key:
            age = await self._get_from_api(domain)
            if age is not None:
                await self._save_to_cache(domain, age)
                return age, "api"

        # Step 4: All methods failed
        logger.warning(f"⚠️ Could not determine age for domain: {domain}")
        return 0, "unknown"

    async def _get_from_library(self, domain: str) -> Optional[int]:
        """Get domain age using python-whois library."""
        try:
            logger.debug(f"📚 Trying local WHOIS library for: {domain}")

            # Run in thread to avoid blocking
            def _whois_lookup():
                w = whois.whois(domain)
                creation_date = w.creation_date

                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                if not creation_date:
                    return None

                # Handle timezone-aware and timezone-naive datetimes
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)

                age = (now - creation_date).days
                return age

            age = await asyncio.to_thread(_whois_lookup)
            if age is not None:
                logger.debug(f"✅ Library lookup successful: {domain} = {age} days")
            return age

        except Exception as e:
            logger.debug(f"❌ Library lookup failed for {domain}: {e}")
            return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def _get_from_api(self, domain: str) -> Optional[int]:
        """Get domain age using WHOIS API with retry logic."""
        try:
            logger.debug(f"🌐 Trying WHOIS API ({self.api_provider}) for: {domain}")

            if self.api_provider == "whoisxml":
                age = await self._query_whoisxml(domain)
            elif self.api_provider == "whoisapi":
                age = await self._query_whoisapi(domain)
            elif self.api_provider == "ipapi":
                age = await self._query_ipapi(domain)
            else:
                logger.warning(f"⚠️ Unknown API provider: {self.api_provider}")
                return None

            if age is not None:
                logger.debug(f"✅ API lookup successful: {domain} = {age} days")
            return age

        except Exception as e:
            logger.debug(f"❌ API lookup failed for {domain}: {e}")
            return None

    async def _query_whoisxml(self, domain: str) -> Optional[int]:
        """Query WhoisXML API."""
        url = self.api_endpoints["whoisxml"]
        params = {"apiKey": self.api_key, "domainName": domain, "outputFormat": "JSON"}

        response = await self.http_client.get(url, params=params)
        response.raise_for_status()

        data = response.json()
        created_date_str = data.get("WhoisRecord", {}).get("createdDate")

        if created_date_str:
            created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - created_date).days
            return age

        return None

    async def _query_whoisapi(self, domain: str) -> Optional[int]:
        """Query WhoisAPI.com."""
        url = self.api_endpoints["whoisapi"]
        params = {"apiKey": self.api_key, "domainName": domain}

        response = await self.http_client.get(url, params=params)
        response.raise_for_status()

        data = response.json()
        created_date_str = data.get("created_date")

        if created_date_str:
            created_date = datetime.fromisoformat(created_date_str)
            age = (datetime.now(timezone.utc) - created_date).days
            return age

        return None

    async def _query_ipapi(self, domain: str) -> Optional[int]:
        """Query ip-api.com (free, limited features)."""
        # Note: ip-api doesn't provide WHOIS data, this is a placeholder
        # You might want to use a different free API or remove this
        logger.warning("⚠️ ip-api doesn't provide domain age, skipping")
        return None

    async def _get_from_cache(self, domain: str) -> Optional[int]:
        """Get domain age from Redis cache."""
        if not self.cache_client:
            return None

        try:
            key = self._cache_key(domain)
            cached_data = await self.cache_client.get(key)

            if cached_data:
                data = json.loads(cached_data)
                age = data.get("age")
                logger.debug(f"💾 Cache hit for domain: {domain} = {age} days")
                return age

        except Exception as e:
            logger.debug(f"Cache read error for {domain}: {e}")

        return None

    async def _save_to_cache(self, domain: str, age: int):
        """Save domain age to Redis cache."""
        if not self.cache_client:
            return

        try:
            key = self._cache_key(domain)
            data = {"age": age, "cached_at": datetime.now().isoformat()}

            await self.cache_client.setex(key, self.cache_ttl, json.dumps(data))
            logger.debug(f"💾 Cached domain age: {domain} = {age} days")

        except Exception as e:
            logger.debug(f"Cache write error for {domain}: {e}")

    def _cache_key(self, domain: str) -> str:
        """Generate cache key for domain."""
        # Use hash to keep keys short
        domain_hash = hashlib.md5(domain.lower().encode()).hexdigest()
        return f"whois:domain:{domain_hash}"

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()


# Global WHOIS client instance
_whois_client_instance: Optional[WhoisClient] = None


async def get_whois_client(cache_client=None) -> WhoisClient:
    """Get or create the global WHOIS client instance."""
    global _whois_client_instance

    if _whois_client_instance is None:
        api_provider = os.getenv("WHOIS_API_PROVIDER", "whoisxml")
        api_key = os.getenv("WHOIS_API_KEY")
        cache_ttl = int(os.getenv("WHOIS_CACHE_TTL", "86400"))

        _whois_client_instance = WhoisClient(
            api_provider=api_provider,
            api_key=api_key,
            cache_client=cache_client,
            cache_ttl=cache_ttl,
        )

    return _whois_client_instance
