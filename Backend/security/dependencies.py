import logging
import os
from typing import Optional
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

def _resolve_limiter(redis_url: Optional[str] = None) -> Limiter:
    """
    Resolve authoritative Limiter configuration for security dependencies.

    Enforces the exact same production contract as the gateway limiter:
    - In production (ZEROPHISH_ENV == 'production'), REDIS_URL is mandatory and
      missing/unreachable Redis fails closed (no silent local memory:// fallback).
    - In non-production (development/test), falls back to in-memory store (memory://)
      if Redis is unreachable or unconfigured.
    """
    env = (os.getenv("ZEROPHISH_ENV") or os.getenv("ENV") or "development").strip().lower()
    is_production = env == "production"
    target_url = redis_url or os.getenv("REDIS_URL")

    if target_url:
        if is_production:
            logger.info("Initializing security dependency limiter with Redis storage: %s", target_url.split("@")[-1])
            return Limiter(
                key_func=get_remote_address,
                default_limits=["60/minute"],
                headers_enabled=False,
                storage_uri=target_url,
                storage_options={
                    "socket_connect_timeout": 3.0,
                    "socket_timeout": 5.0,
                },
            )
        else:
            try:
                candidate = Limiter(
                    key_func=get_remote_address,
                    default_limits=["60/minute"],
                    headers_enabled=False,
                    storage_uri=target_url,
                    storage_options={
                        "socket_connect_timeout": 0.5,
                        "socket_timeout": 0.5,
                    },
                )
                storage = getattr(getattr(candidate, "_limiter", None), "storage", None)
                if storage and hasattr(storage, "check") and storage.check():
                    logger.info("Connected to Redis distributed rate limiter storage in development")
                    return candidate
                logger.warning("Configured REDIS_URL unreachable in development; falling back to local in-memory rate limiter")
            except Exception as e:
                logger.warning("Redis rate limiter initialization failed in development (%s); falling back to in-memory", e)

    if is_production:
        logger.critical("FATAL: Distributed rate limiter requires REDIS_URL in production environment.")
        raise RuntimeError("REDIS_URL must be configured and available in production environment for distributed rate limiting.")

    logger.info("Initializing local in-memory security rate limiter (single-worker development only)")
    return Limiter(
        key_func=get_remote_address,
        default_limits=["60/minute"],
        headers_enabled=False,
        storage_uri="memory://",
    )

limiter: Limiter = _resolve_limiter()