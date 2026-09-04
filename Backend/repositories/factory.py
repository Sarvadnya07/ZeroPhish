"""
Repository Factory & Dependency Injection Provider.

Routes to SQLAlchemy when DATABASE_URL is configured, and defaults to in‑memory for testing/dev.
Enforces explicit fail‑closed error if DATABASE_URL is missing in production.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, cast

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


def _check_production_persistence_requirement() -> None:
    """Fail closed in production if DATABASE_URL is missing."""
    env = (os.getenv("ZEROPHISH_ENV") or os.getenv("ENV", "development")).lower()
    if env == "production" and not os.getenv("DATABASE_URL"):
        logger.critical("FATAL: DATABASE_URL is not set in production mode.")
        raise RuntimeError("DATABASE_URL must be configured in production environment.")


def _get_session_factory():
    """Lazy import of database session factory."""
    from infrastructure.database import _SessionFactory, init_db

    init_db()
    return _SessionFactory


def get_user_repository() -> UserRepository:
    global _user_repo
    if _user_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from .sql_repositories import SQLUserRepository

            _user_repo = SQLUserRepository(_get_session_factory())
        else:
            from .in_memory import InMemoryUserRepository

            _user_repo = cast(UserRepository, InMemoryUserRepository())
            logger.info("Using InMemoryUserRepository (no DATABASE_URL).")
    assert _user_repo is not None
    return _user_repo


def get_incident_repository() -> IncidentRepository:
    global _incident_repo
    if _incident_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from .sql_repositories import SQLIncidentRepository

            _incident_repo = SQLIncidentRepository(_get_session_factory())
        else:
            from .in_memory import InMemoryIncidentRepository

            _incident_repo = cast(IncidentRepository, InMemoryIncidentRepository())
            logger.info("Using InMemoryIncidentRepository (no DATABASE_URL).")
    assert _incident_repo is not None
    return _incident_repo


def get_analytics_repository() -> AnalyticsRepository:
    global _analytics_repo
    if _analytics_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from .sql_repositories import SQLAnalyticsRepository

            _analytics_repo = SQLAnalyticsRepository(_get_session_factory())
        else:
            from .in_memory import InMemoryAnalyticsRepository

            _analytics_repo = cast(AnalyticsRepository, InMemoryAnalyticsRepository())
            logger.info("Using InMemoryAnalyticsRepository (no DATABASE_URL).")
    assert _analytics_repo is not None
    return _analytics_repo


def get_webhook_repository() -> WebhookRepository:
    global _webhook_repo
    if _webhook_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from .sql_repositories import SQLWebhookRepository

            _webhook_repo = SQLWebhookRepository(_get_session_factory())
        else:
            from .in_memory import InMemoryWebhookRepository

            _webhook_repo = cast(WebhookRepository, InMemoryWebhookRepository())
            logger.info("Using InMemoryWebhookRepository (no DATABASE_URL).")
    assert _webhook_repo is not None
    return _webhook_repo


def get_scan_result_repository() -> ScanResultRepository:
    global _scan_result_repo
    if _scan_result_repo is None:
        _check_production_persistence_requirement()
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            from .sql_repositories import SQLScanResultRepository

            _scan_result_repo = SQLScanResultRepository(_get_session_factory())
        else:
            from .in_memory import InMemoryScanResultRepository

            _scan_result_repo = cast(ScanResultRepository, InMemoryScanResultRepository())
            logger.info("Using InMemoryScanResultRepository (no DATABASE_URL).")
    assert _scan_result_repo is not None
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
                        self._client = aioredis.from_url(
                            url,
                            decode_responses=True,
                            socket_connect_timeout=0.5,
                            socket_timeout=0.5,
                        )
                        from .in_memory import InMemoryCacheBackend

                        self._fallback = InMemoryCacheBackend(default_ttl)

                    async def get(self, key: str) -> Optional[str]:
                        try:
                            val = await self._client.get(key)
                            if val is not None:
                                return val
                        except Exception as e:
                            logger.debug("Redis get error for %s: %s", key, e)
                        return await self._fallback.get(key)

                    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
                        try:
                            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
                            await self._client.set(key, value, ex=ttl)
                        except Exception as e:
                            logger.debug("Redis set error for %s: %s", key, e)
                        await self._fallback.set(key, value, ttl_seconds=ttl_seconds)

                    async def delete(self, key: str) -> bool:
                        res = False
                        try:
                            res = bool(await self._client.delete(key))
                        except Exception:
                            pass
                        fb_res = await self._fallback.delete(key)
                        return res or fb_res

                    async def clear_prefix(self, prefix: str) -> int:
                        cleared = 0
                        try:
                            keys = await self._client.keys(f"{prefix}*")
                            if keys:
                                cleared = await self._client.delete(*keys)
                        except Exception:
                            pass
                        cleared_fb = await self._fallback.clear_prefix(prefix)
                        return max(cleared, cleared_fb)

                    async def get_stats(self) -> Dict[str, Any]:
                        try:
                            info = await self._client.info()
                            return {
                                "status": "connected",
                                "backend": "redis",
                                "keys_count": info.get("db0", {}).get("keys", 0),
                            }
                        except Exception:
                            fb_stats = await self._fallback.get_stats()
                            fb_stats["backend"] = "in_memory (redis_fallback)"
                            return fb_stats

                _cache_backend = _RedisCache(redis_url)
                logger.info("Redis cache backend initialized.")
            except Exception as e:
                logger.warning("Failed to initialize Redis cache: %s. Falling back to in‑memory.", e)
                from .in_memory import InMemoryCacheBackend

                _cache_backend = InMemoryCacheBackend()
        else:
            from .in_memory import InMemoryCacheBackend

            _cache_backend = cast(CacheBackend, InMemoryCacheBackend())
            logger.info("Using InMemoryCacheBackend (no REDIS_URL).")
    return _cache_backend


# Setter functions for dependency injection in tests
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
    """Reset all repository singletons for isolated testing."""
    global _user_repo, _incident_repo, _analytics_repo, _webhook_repo, _scan_result_repo, _cache_backend
    _user_repo = None
    _incident_repo = None
    _analytics_repo = None
    _webhook_repo = None
    _scan_result_repo = None
    _cache_backend = None