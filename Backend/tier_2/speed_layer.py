# speed_layer.py - Unified Cache Layer
import asyncio
import hashlib
import json
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Dict, Optional


class InMemoryCache:
    """In-memory cache that works without Redis."""

    def __init__(self, max_size: int = 1000, ttl: int = 300):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.hits = 0
        self.misses = 0

    def _generate_key(self, sender: str, body: str) -> str:
        """Generate a unique cache key using SHA-256."""
        content = f"{sender}:{body}"
        return f"scan:{hashlib.sha256(content.encode()).hexdigest()[:32]}"

    def _clean_expired(self):
        """Remove expired entries from cache."""
        now = datetime.now()
        expired_keys = []

        for key, (data, timestamp) in self.cache.items():
            if (now - timestamp).seconds > self.ttl:
                expired_keys.append(key)

        for key in expired_keys:
            del self.cache[key]

    async def get_cached_result(self, sender: str, body: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached scan result if available."""
        self._clean_expired()

        key = self._generate_key(sender, body)
        if key in self.cache:
            data, timestamp = self.cache.pop(key)
            self.cache[key] = (data, timestamp)
            self.hits += 1
            return data

        self.misses += 1
        return None

    async def set_cached_result(self, sender: str, body: str, result: Dict[str, Any]):
        """Cache scan result."""
        self._clean_expired()

        key = self._generate_key(sender, body)

        result_with_meta = {
            **result,
            "_cached_at": datetime.now().isoformat(),
            "_ttl": self.ttl,
            "_cache_type": "memory",
        }

        self.cache[key] = (result_with_meta, datetime.now())

        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        self._clean_expired()

        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0

        return {
            "status": "connected",
            "cache_type": "memory",
            "cache_size": len(self.cache),
            "max_size": self.max_size,
            "ttl": self.ttl,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.1f}%",
        }

    async def clear_cache(self):
        """Clear all cached scan results."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        print("✅ In-memory cache cleared")

    async def disconnect(self):
        """For compatibility."""
        pass


# Create a global cache instance
cache = InMemoryCache()


async def init_cache():
    """Initialize the cache."""
    print("✅ In-memory cache initialized")
    return cache
