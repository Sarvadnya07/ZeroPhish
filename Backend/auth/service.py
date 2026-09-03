"""
ZeroPhish Auth Service — Identity mapping, user provisioning, and RBAC management.

Integrates with Clerk as the identity authority. Manages the mapping between
Clerk user IDs and internal ZeroPhish user profiles, including roles and status.

This service is the single source of truth for user profiles.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from repositories.factory import get_user_repository
from security.audit_logger import AuditLogger

from .models import User, UserInDB, UserRole, UserStatus, UserUpdate

logger = logging.getLogger(__name__)

# In-memory fallback / test stores
_users_by_id: Dict[str, UserInDB] = {}
_users_by_email: Dict[str, UserInDB] = {}
_users_by_clerk_id: Dict[str, UserInDB] = {}
_IN_MEMORY_STORE = _users_by_id

def _store_user_in_memory(u: UserInDB) -> None:
    _users_by_id[u.id] = u
    if u.email:
        _users_by_email[u.email.lower()] = u
    if u.clerk_user_id:
        _users_by_clerk_id[u.clerk_user_id] = u

def _remove_user_from_memory(user_id: str) -> None:
    u = _users_by_id.pop(user_id, None)
    if u:
        if u.email:
            _users_by_email.pop(u.email.lower(), None)
        if u.clerk_user_id:
            _users_by_clerk_id.pop(u.clerk_user_id, None)

def _maybe_await(res: Any) -> Any:
    import inspect
    import asyncio
    if inspect.isawaitable(res):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(res)).result()
        else:
            return asyncio.run(res)
    return res


class AuthService:
    """User profile mapping and role-based access control service."""

    @classmethod
    def _get_repository(cls):
        """Retrieve the user repository, falling back to in-memory if unavailable."""
        try:
            repo = get_user_repository()
            return repo
        except Exception as e:
            logger.warning("Repository unavailable, using in-memory fallback: %s", e)
            return None

    @classmethod
    def _to_model(cls, user_db: UserInDB) -> User:
        """Convert a repository user entity to the application User model."""
        return User(**user_db.model_dump())

    @classmethod
    def _get_admin_emails(cls) -> List[str]:
        """Return the list of admin emails from environment."""
        raw = os.getenv("ADMIN_EMAIL", "")
        if not raw:
            return []
        return [e.strip().lower() for e in raw.split(",") if e.strip()]

    @classmethod
    def _get_admin_clerk_ids(cls) -> List[str]:
        """Return the list of admin Clerk user IDs from environment."""
        raw = os.getenv("CLERK_ADMIN_USER_IDS", "")
        if not raw:
            return []
        return [cid.strip() for cid in raw.split(",") if cid.strip()]

    @classmethod
    def get_or_create_user(
        cls,
        clerk_user_id: str,
        email: str,
        full_name: str,
        role: Optional[UserRole] = None,
    ) -> User:
        """
        Load an existing application user by Clerk User ID or safely provision
        a new user profile with least-privilege (USER) role.

        The method performs:
        1. Lookup by clerk_user_id in repository (and fallback in-memory)
        2. If not found, try email to migrate legacy users
        3. If still not found, provision a new user

        Returns the application User model.
        """
        if not clerk_user_id or not email:
            raise ValueError("clerk_user_id and email are required")

        email = email.lower().strip()
        full_name = full_name.strip() or email.split("@")[0]

        repo = cls._get_repository()
        user_db = None

        # 1. Lookup by clerk_user_id
        if repo:
            user_db = repo.get_by_clerk_id(clerk_user_id)
        if not user_db:
            user_db = _users_by_clerk_id.get(clerk_user_id)

        # 2. If not found, try by email (legacy migration)
        if not user_db and email:
            if repo:
                user_db = repo.get_by_email(email)
            if not user_db:
                user_db = _users_by_email.get(email)
            if user_db:
                # Update the existing user with the Clerk ID (migrate)
                user_db.clerk_user_id = clerk_user_id
                user_db.last_login = datetime.now(timezone.utc)
                if repo:
                    repo.save(user_db)
                _store_user_in_memory(user_db)

        if user_db:
            # Update last_login
            user_db.last_login = datetime.now(timezone.utc)
            if repo:
                repo.save(user_db)
            _store_user_in_memory(user_db)
            return cls._to_model(user_db)

        # 3. Provision new user
        admin_emails = cls._get_admin_emails()
        admin_clerk_ids = cls._get_admin_clerk_ids()

        if role:
            initial_role = role
        elif email in admin_emails or clerk_user_id in admin_clerk_ids:
            initial_role = UserRole.ADMIN
        else:
            initial_role = UserRole.USER

        new_id = str(uuid4())
        user_in_db = UserInDB(
            id=new_id,
            clerk_user_id=clerk_user_id,
            email=email,
            full_name=full_name,
            role=initial_role,
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc),
            scan_count=0,
            risk_score=0.0,
        )

        if repo:
            repo.save(user_in_db)
        _store_user_in_memory(user_in_db)

        AuditLogger.log_event(
            event_type="USER_PROVISIONED",
            user_id=new_id,
            details={
                "clerk_user_id": clerk_user_id,
                "email": email,
                "role": initial_role.value,
            },
        )
        logger.info("User provisioned: %s (%s)", email, initial_role.value)

        return cls._to_model(user_in_db)

    @classmethod
    def get_user_by_id(cls, user_id: str) -> Optional[User]:
        """Retrieve a user by internal ID."""
        repo = cls._get_repository()
        user_db = None
        if repo:
            user_db = repo.get_by_id(user_id)
        if not user_db:
            user_db = _users_by_id.get(user_id)
        if not user_db:
            return None
        return cls._to_model(user_db)

    @classmethod
    def get_user_by_clerk_id(cls, clerk_user_id: str) -> Optional[User]:
        """Retrieve a user by Clerk user ID."""
        if not clerk_user_id:
            return None
        repo = cls._get_repository()
        user_db = None
        if repo:
            user_db = repo.get_by_clerk_id(clerk_user_id)
        if not user_db:
            user_db = _users_by_clerk_id.get(clerk_user_id)
        if not user_db:
            return None
        return cls._to_model(user_db)

    @classmethod
    def update_user(cls, user_id: str, update: UserUpdate) -> Optional[User]:
        """
        Update a user's profile.

        Only fields present in UserUpdate will be updated. If the update would
        downgrade the last admin, we log a warning but allow it (enforce via business logic).
        """
        if not user_id:
            raise ValueError("user_id is required")

        repo = cls._get_repository()
        user_db = None

        if repo:
            user_db = repo.update(user_id, update)
        if not user_db and user_id in _users_by_id:
            user_db = _users_by_id[user_id]
            if update.full_name is not None:
                user_db.full_name = update.full_name.strip()
            if update.role is not None:
                user_db.role = update.role
            if update.status is not None:
                user_db.status = update.status
            # Persist to repo if available
            if repo:
                repo.save(user_db)
            _store_user_in_memory(user_db)

        if user_db:
            # If we're downgrading an admin, log it
            old_role = user_db.role
            if update.role is not None and old_role == UserRole.ADMIN and update.role != UserRole.ADMIN:
                logger.warning("Admin user %s downgraded to %s", user_id, update.role.value)
                AuditLogger.log_event(
                    event_type="ADMIN_DOWNGRADE",
                    user_id=user_id,
                    details={"new_role": update.role.value},
                )
            return cls._to_model(user_db)

        return None

    @classmethod
    def list_users(cls, role: Optional[UserRole] = None) -> List[User]:
        """List all users, optionally filtered by role."""
        repo = cls._get_repository()
        users = []
        if repo:
            users = repo.list_all(role=role)
        else:
            users = list(_users_by_id.values())
            if role:
                users = [u for u in users if u.role == role]
        return [cls._to_model(u) for u in users]

    @classmethod
    def delete_user(cls, user_id: str) -> bool:
        """Delete a user by ID. Returns True if deleted, False otherwise."""
        if not user_id:
            return False
        repo = cls._get_repository()
        ok = False
        if repo:
            ok = repo.delete(user_id)
        if user_id in _users_by_id:
            _remove_user_from_memory(user_id)
            ok = True
        return ok