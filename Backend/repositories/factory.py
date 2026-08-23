"""
Repository Factory & Dependency Injection Provider.
Routes to SQLAlchemy when DATABASE_URL is configured, and defaults to in-memory for testing/dev.
Lazy loading ensures complete immunity to circular imports.
"""
from __future__ import annotations

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

_user_repo: Optional[UserRepository] = None
_incident_repo: Optional[IncidentRepository] = None
_analytics_repo: Optional[AnalyticsRepository] = None
_webhook_repo: Optional[WebhookRepository] = None
_scan_result_repo: Optional[ScanResultRepository] = None
_cache_backend: Optional[CacheBackend] = None


def get_user_repository() -> UserRepository:
    global _user_repo
    if _user_repo is None:
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
        from .in_memory import InMemoryAnalyticsRepository
        _analytics_repo = InMemoryAnalyticsRepository()
    return _analytics_repo


def get_webhook_repository() -> WebhookRepository:
    global _webhook_repo
    if _webhook_repo is None:
        from .in_memory import InMemoryWebhookRepository
        _webhook_repo = InMemoryWebhookRepository()
    return _webhook_repo


def get_scan_result_repository() -> ScanResultRepository:
    global _scan_result_repo
    if _scan_result_repo is None:
        from .in_memory import InMemoryScanResultRepository
        _scan_result_repo = InMemoryScanResultRepository()
    return _scan_result_repo


def get_cache_backend() -> CacheBackend:
    global _cache_backend
    if _cache_backend is None:
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
