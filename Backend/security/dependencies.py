import logging
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

def _get_security_limiter() -> Limiter:
    target_url = os.getenv("REDIS_URL")
    if target_url:
        try:
            candidate = Limiter(
                key_func=get_remote_address,
                default_limits=["60/minute"],
                headers_enabled=False,
                storage_uri=target_url,
                storage_options={"socket_connect_timeout": 0.5, "socket_timeout": 0.5},
            )
            storage = getattr(getattr(candidate, "_limiter", None), "storage", None)
            if storage and hasattr(storage, "check") and storage.check():
                return candidate
        except Exception as e:
            logger.debug("Failed initializing Redis storage for security limiter: %s", e)
    return Limiter(
        key_func=get_remote_address,
        default_limits=["60/minute"],
        headers_enabled=False,
        storage_uri="memory://",
    )

limiter = _get_security_limiter()