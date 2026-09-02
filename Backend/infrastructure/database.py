"""
Database engine, session management, and Base model for SQLAlchemy 2.x.
Supports SQLite (local dev/test) and PostgreSQL (production).

This module provides:
- DeclarativeBase for ORM models
- Engine creation with pooling and proper configuration
- Session management via FastAPI dependency
- Automatic table creation (init_db)
"""

from __future__ import annotations

import os
import logging
from typing import Generator, Optional

from sqlalchemy import create_engine, event  # type: ignore[reportMissingImports]
from sqlalchemy.engine import Engine  # type: ignore[reportMissingImports]
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker  # type: ignore[reportMissingImports]

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ---------- Configuration ----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.warning("DATABASE_URL environment variable not set; database features will be unavailable.")


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _is_postgresql(url: str) -> bool:
    return url.startswith("postgresql") or url.startswith("postgres")


def _create_engine(url: str) -> Engine:
    """Create SQLAlchemy engine with appropriate configuration."""
    connect_args = {}
    pool_config = {}

    if _is_sqlite(url):
        connect_args = {"check_same_thread": False}
        # SQLite doesn't support pooling effectively; use NullPool or leave default.
        # We'll keep default pool (null pool) for SQLite.
    elif _is_postgresql(url):
        # PostgreSQL: use a connection pool with reasonable limits
        pool_config = {
            "pool_size": int(os.getenv("DB_POOL_SIZE", "5")),
            "max_overflow": int(os.getenv("DB_POOL_MAX_OVERFLOW", "10")),
            "pool_pre_ping": True,
            "pool_recycle": 3600,
        }

    engine = create_engine(
        url,
        connect_args=connect_args,
        **pool_config,
        echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    )

    # For SQLite, enable foreign key constraints
    if _is_sqlite(url):
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    logger.info("Database engine created for %s", url.split("://")[0])
    return engine


# ---------- Engine and Session Factory ----------
_engine: Optional[Engine] = None
_SessionFactory: Optional[sessionmaker] = None

if DATABASE_URL:
    _engine = _create_engine(DATABASE_URL)
    _SessionFactory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=_engine,
        expire_on_commit=False,  # Better for async-like patterns
    )


def get_engine() -> Optional[Engine]:
    """Return the database engine instance."""
    return _engine


def get_session_factory() -> Optional[sessionmaker]:
    """Return the session factory."""
    return _SessionFactory


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session.

    Usage:
        @app.get("/items")
        def read_items(db: Session = Depends(get_db)):
            ...
    """
    if not _SessionFactory:
        raise RuntimeError("DATABASE_URL is not configured. Set DATABASE_URL environment variable.")
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables if the engine is configured."""
    if _engine:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=_engine)
        logger.info("Database tables created.")
    else:
        logger.warning("Cannot initialize database: DATABASE_URL not set.")