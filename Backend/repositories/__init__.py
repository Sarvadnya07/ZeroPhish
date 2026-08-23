"""
ZeroPhish Repositories Package.
"""
from __future__ import annotations

from .base import (
    AnalyticsRepository,
    CacheBackend,
    IncidentRepository,
    ScanResultRepository,
    UserRepository,
    WebhookRepository,
)
from .factory import (
    get_analytics_repository,
    get_cache_backend,
    get_incident_repository,
    get_scan_result_repository,
    get_user_repository,
    get_webhook_repository,
    reset_repositories,
    set_analytics_repository,
    set_cache_backend,
    set_incident_repository,
    set_scan_result_repository,
    set_user_repository,
    set_webhook_repository,
)

__all__ = [
    "UserRepository",
    "IncidentRepository",
    "AnalyticsRepository",
    "WebhookRepository",
    "ScanResultRepository",
    "CacheBackend",
    "get_user_repository",
    "get_incident_repository",
    "get_analytics_repository",
    "get_webhook_repository",
    "get_scan_result_repository",
    "get_cache_backend",
    "set_user_repository",
    "set_incident_repository",
    "set_analytics_repository",
    "set_webhook_repository",
    "set_scan_result_repository",
    "set_cache_backend",
    "reset_repositories",
]
