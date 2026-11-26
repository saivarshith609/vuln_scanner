"""
Alembic environment configuration.

Reads the DATABASE_URL from the application settings (via pydantic-settings)
so that Alembic uses the same connection string as the running app.
All model metadata is imported so autogenerate works correctly.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ── Application integration ──────────────────────────────────────────────────
from app.core.config import get_settings
from app.db.base import Base

# Import all models so Base.metadata is fully populated
import app.models  # noqa: F401

# Alembic Config object — gives access to alembic.ini values.
config = context.config

# Override the INI sqlalchemy.url with the app's DATABASE_URL
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Python logging from the INI file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL script generation)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against a live database."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
