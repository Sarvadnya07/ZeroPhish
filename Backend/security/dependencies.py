from slowapi import Limiter
from slowapi.util import get_remote_address

# Configure rate limiter with custom settings
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],  # Default limit
    headers_enabled=True,  # Return Retry-After header
    storage_uri="memory://",  # Use in-memory store (or Redis for production)
)