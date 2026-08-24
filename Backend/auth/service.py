"""
ZeroPhish Auth Service — Identity mapping, user provisioning, and RBAC management.
Integrates with Clerk as the identity authority.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Dict, List, Optional

from repositories.factory import get_user_repository
from security.audit_logger import AuditLogger

from .models import User, UserInDB, UserRole, UserStatus, UserUpdate

logger = logging.getLogger(__name__)

# Direct state references for backwards-compatible test access
_users_by_id: Dict[str, UserInDB] = {}
_users_by_email: Dict[str, str] = {}
_users_by_clerk_id: Dict[str, str] = {}


class AuthService:
    """User profile mapping and role-based access control service."""

    @classmethod
    def get_or_create_user(
        cls,
        clerk_user_id: str,
        email: str,
        full_name: str,
        role: Optional[UserRole] = None,
    ) -> User:
        """
        Loads an existing application user by Clerk User ID or safely provisions
        a new user profile with least-privilege (USER) role.
        """
        repo = get_user_repository()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 1. Lookup by clerk_user_id
        existing = repo.get_by_clerk_id(clerk_user_id) if hasattr(repo, "get_by_clerk_id") else None
        if not existing:
            # Fallback lookup in memory state
            uid = _users_by_clerk_id.get(clerk_user_id)
            if uid:
                existing = _users_by_id.get(uid)

        # 2. Migration lookup: check if email exists from legacy user records
        if not existing and email:
            existing_by_email = repo.get_by_email(email)
            if not existing_by_email:
                uid_email = _users_by_email.get(email.lower().strip())
                if uid_email:
                    existing_by_email = _users_by_id.get(uid_email)

            if existing_by_email:
                existing_by_email.clerk_user_id = clerk_user_id
                existing_by_email.last_login = now
                repo.save(existing_by_email)
                _users_by_id[existing_by_email.id] = existing_by_email
                _users_by_clerk_id[clerk_user_id] = existing_by_email.id
                return User(**existing_by_email.model_dump())

        if existing:
            existing.last_login = now
            repo.save(existing)
            _users_by_id[existing.id] = existing
            _users_by_clerk_id[clerk_user_id] = existing.id
            return User(**existing.model_dump())

        # 3. Provision new application user (least privilege default)
        admin_emails = [
            e.strip().lower()
            for e in os.getenv("ADMIN_EMAIL", "admin@example.com").split(",")
            if e.strip()
        ]
        admin_clerk_ids = [
            cid.strip()
            for cid in os.getenv("CLERK_ADMIN_USER_IDS", "").split(",")
            if cid.strip()
        ]

        if role:
            initial_role = role
        elif clerk_user_id in admin_clerk_ids or email.lower().strip() in admin_emails:
            initial_role = UserRole.ADMIN
        else:
            initial_role = UserRole.USER

        new_uid = str(uuid.uuid4())
        user_in_db = UserInDB(
            id=new_uid,
            clerk_user_id=clerk_user_id,
            email=email.lower().strip(),
            full_name=full_name or email.split("@")[0],
            role=initial_role,
            status=UserStatus.ACTIVE,
            created_at=now,
            last_login=now,
        )

        repo.save(user_in_db)
        _users_by_id[user_in_db.id] = user_in_db
        _users_by_email[user_in_db.email] = user_in_db.id
        _users_by_clerk_id[clerk_user_id] = user_in_db.id

        AuditLogger.log_event(
            event_type="USER_PROVISIONED",
            user_id=new_uid,
            details={"clerk_user_id": clerk_user_id, "role": initial_role.value},
        )

        return User(**user_in_db.model_dump())

    @classmethod
    def get_user_by_id(cls, user_id: str) -> Optional[User]:
        repo = get_user_repository()
        user_db = repo.get_by_id(user_id) or _users_by_id.get(user_id)
        if not user_db:
            return None
        return User(**user_db.model_dump())

    @classmethod
    def get_user_by_clerk_id(cls, clerk_user_id: str) -> Optional[User]:
        repo = get_user_repository()
        user_db = (
            repo.get_by_clerk_id(clerk_user_id) if hasattr(repo, "get_by_clerk_id") else None
        )
        if not user_db:
            uid = _users_by_clerk_id.get(clerk_user_id)
            if uid:
                user_db = _users_by_id.get(uid)
        if not user_db:
            return None
        return User(**user_db.model_dump())

    @classmethod
    def update_user(cls, user_id: str, update: UserUpdate) -> Optional[User]:
        repo = get_user_repository()
        user_db = repo.update(user_id, update)
        if not user_db:
            existing = _users_by_id.get(user_id)
            if existing:
                if update.full_name is not None:
                    existing.full_name = update.full_name
                if update.role is not None:
                    existing.role = update.role
                if update.status is not None:
                    existing.status = update.status
                user_db = existing

        if user_db:
            _users_by_id[user_id] = user_db
            return User(**user_db.model_dump())
        return None

    @classmethod
    def list_users(cls, role: Optional[UserRole] = None) -> List[User]:
        repo = get_user_repository()
        users = repo.list_all(role=role)
        if not users:
            users = list(_users_by_id.values())
            if role:
                users = [u for u in users if u.role == role]
        return [User(**u.model_dump()) for u in users]

    @classmethod
    def delete_user(cls, user_id: str) -> bool:
        repo = get_user_repository()
        ok = repo.delete(user_id)
        u = _users_by_id.pop(user_id, None)
        if u:
            _users_by_email.pop(u.email, None)
            _users_by_clerk_id.pop(u.clerk_user_id, None)
            ok = True
        return ok
