"""
Database engine, session management, and Base model for SQLAlchemy 2.x.
Supports SQLite (local dev/test) and PostgreSQL (production).
"""
from __future__ import annotations

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


DATABASE_URL = os.getenv("DATABASE_URL")

# Configure engine if DATABASE_URL is set
_engine = None
_SessionFactory = None

if DATABASE_URL:
    # Ensure SQLite handles multi-threading correctly
    connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    _engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
    _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def get_engine():
    return _engine


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    if not _SessionFactory:
        raise RuntimeError("DATABASE_URL is not configured.")
    db = _SessionFactory()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create tables if engine is configured."""
    if _engine:
        Base.metadata.create_all(bind=_engine)
