"""
ZeroPhish Repository Protocols & Domain Interfaces.

Lightweight Python Protocols defining clear data‑access seams.
Each protocol defines the contract for a repository that can be implemented
with in‑memory, SQL, or other backends.
"""

from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    runtime_checkable,
    Union,
)

if TYPE_CHECKING:
    from analytics.models import (
        AdminDashboardSummary,
        FalsePositiveReport,
        ModelMetrics,
        PolicyRule,
        ThreatFeedItem,
        ThreatHeatmapEntry,
    )
    from auth.models import User, UserInDB, UserRole, UserUpdate
    from incidents.models import (
        Incident,
        IncidentComment,
        IncidentSeverity,
        IncidentStatus,
        IncidentUpdate,
    )
    from webhooks.models import WebhookDelivery, WebhookSubscription


@runtime_checkable
class UserRepository(Protocol):
    """Repository for user profiles and authentication tokens."""

    async def get_by_id(self, user_id: str) -> Optional[Any]:
        """Retrieve a user by internal ID."""
        ...

    async def get_by_clerk_id(self, clerk_user_id: str) -> Optional[Any]:
        """Retrieve a user by Clerk user ID."""
        ...

    async def get_by_email(self, email: str) -> Optional[Any]:
        """Retrieve a user by email address."""
        ...

    async def save(self, user: Any) -> Any:
        """Save a user record (insert or update)."""
        ...

    async def list_all(self, role: Optional[Any] = None) -> List[Any]:
        """List all users, optionally filtered by role."""
        ...

    async def update(self, user_id: str, update: Any) -> Optional[Any]:
        """Update a user's fields (provided in update object)."""
        ...

    async def delete(self, user_id: str) -> bool:
        """Delete a user by ID. Returns True if deleted."""
        ...

    async def increment_scan(self, user_id: str, final_score: float) -> None:
        """Increment scan count and update risk score for a user."""
        ...

    async def store_token(self, token: str, user_id: str, expires_at: float) -> None:
        """Store a revocation record for a token."""
        ...

    async def validate_token(self, token: str) -> Optional[Any]:
        """Validate a token; returns user if valid, None otherwise."""
        ...

    async def revoke_token(self, token: str) -> None:
        """Revoke a token (delete revocation record)."""
        ...


@runtime_checkable
class IncidentRepository(Protocol):
    """Repository for incident tickets."""

    async def save(self, incident: Any) -> Any:
        """Save an incident (insert or update)."""
        ...

    async def get_by_id(self, incident_id: str) -> Optional[Any]:
        """Retrieve an incident by ID."""
        ...

    async def list_all(
        self,
        status: Optional[Any] = None,
        severity: Optional[Any] = None,
        assignee_id: Optional[str] = None,
        reporter_id: Optional[str] = None,
    ) -> List[Any]:
        """List incidents with optional filters."""
        ...

    async def update(self, incident_id: str, update: Any) -> Optional[Any]:
        """Update an incident."""
        ...

    async def add_comment(self, incident_id: str, comment: Any) -> Optional[Any]:
        """Add a comment to an incident."""
        ...

    async def delete(self, incident_id: str) -> bool:
        """Delete an incident. Returns True if deleted."""
        ...

    async def stats(self) -> Dict[str, Any]:
        """Return summary statistics about incidents."""
        ...


@runtime_checkable
class AnalyticsRepository(Protocol):
    """Repository for analytics, telemetry, and policies."""

    async def record_scan_event(self, event: Dict[str, Any]) -> None:
        """Record a scan event for analytics."""
        ...

    async def get_scan_events(self, limit: int = 10000) -> List[Dict[str, Any]]:
        """Retrieve recent scan events."""
        ...

    async def get_dashboard_summary(self) -> Any:
        """Return the admin dashboard summary."""
        ...

    async def get_threat_heatmap(self) -> List[Any]:
        """Return threat heatmap data."""
        ...

    async def get_threat_feed(self, limit: int = 50) -> List[Any]:
        """Return recent threat feed items."""
        ...

    async def get_model_metrics(self) -> Any:
        """Return ML model performance metrics."""
        ...

    async def update_model_metrics(self, fp_delta: int = 0, fn_delta: int = 0) -> None:
        """Update model metrics with false‑positive/negative deltas."""
        ...

    async def save_false_positive(self, report: Any) -> Any:
        """Save a false‑positive report."""
        ...

    async def list_false_positives(self, reviewed: Optional[bool] = None) -> List[Any]:
        """List false‑positive reports, optionally filtered by review status."""
        ...

    async def review_false_positive(
        self, fp_id: str, reviewer_id: str, resolution: str
    ) -> Optional[Any]:
        """Mark a false‑positive report as reviewed."""
        ...

    async def save_policy_rule(self, rule: Any) -> Any:
        """Save a policy rule."""
        ...

    async def list_policy_rules(self) -> List[Any]:
        """List all policy rules."""
        ...

    async def delete_policy_rule(self, rule_id: str) -> bool:
        """Delete a policy rule. Returns True if deleted."""
        ...


@runtime_checkable
class WebhookRepository(Protocol):
    """Repository for webhook subscriptions and delivery logs."""

    async def save_subscription(self, subscription: Any) -> Any:
        """Save a webhook subscription."""
        ...

    async def get_subscription(self, sub_id: str) -> Optional[Any]:
        """Retrieve a subscription by ID."""
        ...

    async def list_subscriptions(self, owner_id: Optional[str] = None) -> List[Any]:
        """List subscriptions, optionally filtered by owner."""
        ...

    async def delete_subscription(self, sub_id: str, owner_id: Optional[str] = None) -> bool:
        """Delete a subscription. Returns True if deleted."""
        ...

    async def record_delivery(self, delivery: Any) -> None:
        """Record a webhook delivery attempt."""
        ...

    async def get_delivery_log(self, limit: int = 100) -> List[Any]:
        """Return recent delivery log entries."""
        ...


@runtime_checkable
class ScanResultRepository(Protocol):
    """Repository for scan result caching."""

    async def save(self, scan_id: str, scan_data: Any) -> None:
        """Save a scan result."""
        ...

    async def get(self, scan_id: str) -> Optional[Any]:
        """Retrieve a scan result by ID."""
        ...

    async def delete(self, scan_id: str) -> bool:
        """Delete a scan result. Returns True if deleted."""
        ...

    async def list_all(self, limit: int = 100) -> List[Any]:
        """List recent scan results."""
        ...

    async def count(self) -> int:
        """Return total number of stored scan results."""
        ...

    async def count_pending(self) -> int:
        """Return number of incomplete (pending) scan results."""
        ...


@runtime_checkable
class CacheBackend(Protocol):
    """Protocol for a cache backend (Redis or in‑memory)."""

    async def get(self, key: str) -> Optional[str]:
        """Retrieve a value by key."""
        ...

    async def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        """Store a value with optional TTL."""
        ...

    async def delete(self, key: str) -> bool:
        """Delete a key. Returns True if deleted."""
        ...

    async def clear_prefix(self, prefix: str) -> int:
        """Delete all keys with a given prefix. Returns count."""
        ...

    async def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        ...