"""
Alembic environment configuration for ZeroPhish database migrations.

This module configures Alembic to work with both SQLite (development) and
PostgreSQL (production) databases. It automatically loads the ORM models
and uses the DATABASE_URL from environment variables.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context  # type: ignore[import-not-found]
from sqlalchemy import engine_from_config, pool  # pyright: ignore[reportMissingImports]

# ────────────────────────────────────────────────────────────────────────────────
# Add Backend to Python path so that models can be imported
# ────────────────────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

# ────────────────────────────────────────────────────────────────────────────────
# Import the ORM models and database configuration
# ────────────────────────────────────────────────────────────────────────────────
# This ensures all models are registered in Base.metadata
import infrastructure.models  # noqa: F401
from infrastructure.database import DATABASE_URL, Base

# ────────────────────────────────────────────────────────────────────────────────
# Alembic Config object
# ────────────────────────────────────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """Return the database URL from environment."""
    url = os.getenv("DATABASE_URL")
    if not url:
        raise ValueError(
            "DATABASE_URL environment variable is not set. "
            "Please set it before running migrations."
        )
    return url


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,  # Detect type changes (e.g., String -> DateTime)
        compare_server_default=True,  # Detect default value changes
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a
    connection with the context.
    """
    url = get_url()
    is_sqlite = url.startswith("sqlite")

    # Build engine configuration
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = url

    # SQLite-specific configuration
    connect_args = {}
    if is_sqlite:
        connect_args = {"check_same_thread": False}

    # For production, use connection pooling
    poolclass = pool.NullPool if is_sqlite else pool.QueuePool

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=poolclass,
        connect_args=connect_args,
        pool_pre_ping=True,  # Verify connection before using
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # For SQLite, we need to handle type differences carefully
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()