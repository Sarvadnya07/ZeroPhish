"""
Repository Factory & Dependency Injection Provider.
Routes to SQLAlchemy when DATABASE_URL is configured, and defaults to in-memory for testing/dev.
Enforces explicit fail-closed error if DATABASE_URL is missing in production.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from .base import (
    AnalyticsRepository,
    CacheBackend,
    IncidentRepository,
    ScanResultRepository,
    UserRepository,
    WebhookRepository,
)

logger = logging.getLogger(__name__)

_user_repo: Optional[UserRepository] = None
_incident_repo: Optional[IncidentRepository] = None
_analytics_repo: Optional[AnalyticsRepository] = None
_webhook_repo: Optional[WebhookRepository] = None
_scan_result_repo: Optional[ScanResultRepository] = None
_cache_backend: Optional[CacheBackend] = None


def _check_production_persistence_requirement():
    """Fail closed in production if DATABASE_URL is missing."""
    if os.getenv("ENV", "development").lower() == "production" and not os.getenv("DATABASE_URL"):
        logger.critical(
            "FATAL: DATABASE_URL is not set in production mode. In-memory fallback rejected."
        )
        raise RuntimeError("DATABASE_URL must be configured in production environment.")


def get_user_repository() -> UserRepository:
    global _user_repo
    if _user_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from infrastructure.database import _SessionFactory, init_db

            from .sql_repositories import SQLUserRepository

            init_db()
            _user_repo = SQLUserRepository(_SessionFactory)
        else:
            from .in_memory import InMemoryUserRepository

            _user_repo = InMemoryUserRepository()
    return _user_repo


def get_incident_repository() -> IncidentRepository:
    global _incident_repo
    if _incident_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from infrastructure.database import _SessionFactory, init_db

            from .sql_repositories import SQLIncidentRepository

            init_db()
            _incident_repo = SQLIncidentRepository(_SessionFactory)
        else:
            from .in_memory import InMemoryIncidentRepository

            _incident_repo = InMemoryIncidentRepository()
    return _incident_repo


def get_analytics_repository() -> AnalyticsRepository:
    global _analytics_repo
    if _analytics_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from infrastructure.database import _SessionFactory, init_db
            from .sql_repositories import SQLAnalyticsRepository

            init_db()
            _analytics_repo = SQLAnalyticsRepository(_SessionFactory)
        else:
            from .in_memory import InMemoryAnalyticsRepository

            _analytics_repo = InMemoryAnalyticsRepository()
    return _analytics_repo


def get_webhook_repository() -> WebhookRepository:
    global _webhook_repo
    if _webhook_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from infrastructure.database import _SessionFactory, init_db
            from .sql_repositories import SQLWebhookRepository

            init_db()
            _webhook_repo = SQLWebhookRepository(_SessionFactory)
        else:
            from .in_memory import InMemoryWebhookRepository

            _webhook_repo = InMemoryWebhookRepository()
    return _webhook_repo


def get_scan_result_repository() -> ScanResultRepository:
    global _scan_result_repo
    if _scan_result_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from infrastructure.database import _SessionFactory, init_db
            from .sql_repositories import SQLScanResultRepository

            init_db()
            _scan_result_repo = SQLScanResultRepository(_SessionFactory)
        else:
            from .in_memory import InMemoryScanResultRepository

            _scan_result_repo = InMemoryScanResultRepository()
    return _scan_result_repo


def get_cache_backend() -> CacheBackend:
    global _cache_backend
    if _cache_backend is None:
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                import redis.asyncio as aioredis

                class _RedisCache:
                    def __init__(self, url: str, default_ttl: int = 300):
                        self._url = url
                        self._default_ttl = default_ttl
                        self._client = aioredis.from_url(url, decode_responses=True)

                    async def get(self, key: str) -> Optional[str]:
                        try:
                            return await self._client.get(key)
                        except Exception as e:
                            logger.debug("Redis cache get error for %s: %s", key, e)
                            return None

                    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
                        try:
                            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
                            await self._client.set(key, value, ex=ttl)
                        except Exception as e:
                            logger.debug("Redis cache set error for %s: %s", key, e)

                    async def delete(self, key: str) -> bool:
                        try:
                            return bool(await self._client.delete(key))
                        except Exception:
                            return False

                    async def clear_prefix(self, prefix: str) -> int:
                        try:
                            keys = await self._client.keys(f"{prefix}*")
                            if keys:
                                return await self._client.delete(*keys)
                            return 0
                        except Exception:
                            return 0

                    async def get_stats(self) -> Dict[str, Any]:
                        try:
                            info = await self._client.info()
                            return {"status": "connected", "backend": "redis", "keys_count": info.get("db0", {}).get("keys", 0)}
                        except Exception as e:
                            return {"status": "error", "backend": "redis", "error": str(e)}

                _cache_backend = _RedisCache(redis_url)
            except Exception as _redis_err:
                logger.warning("Failed to initialize Redis cache, falling back to in-memory: %s", _redis_err)
                from .in_memory import InMemoryCacheBackend

                _cache_backend = InMemoryCacheBackend()
        else:
            from .in_memory import InMemoryCacheBackend

            _cache_backend = InMemoryCacheBackend()
    return _cache_backend


def set_user_repository(repo: UserRepository) -> None:
    global _user_repo
    _user_repo = repo


def set_incident_repository(repo: IncidentRepository) -> None:
    global _incident_repo
    _incident_repo = repo


def set_analytics_repository(repo: AnalyticsRepository) -> None:
    global _analytics_repo
    _analytics_repo = repo


def set_webhook_repository(repo: WebhookRepository) -> None:
    global _webhook_repo
    _webhook_repo = repo


def set_scan_result_repository(repo: ScanResultRepository) -> None:
    global _scan_result_repo
    _scan_result_repo = repo


def set_cache_backend(cache: CacheBackend) -> None:
    global _cache_backend
    _cache_backend = cache


def reset_repositories() -> None:
    """Reset repository singletons for isolated testing."""
    global _user_repo, _incident_repo, _analytics_repo, _webhook_repo, _scan_result_repo, _cache_backend
    _user_repo = None
    _incident_repo = None
    _analytics_repo = None
    _webhook_repo = None
    _scan_result_repo = None
    _cache_backend = None
