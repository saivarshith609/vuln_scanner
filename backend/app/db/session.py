"""
VulnScanner API — Database session management.

Provides engine creation, session factory, and the FastAPI ``get_db``
dependency.  No connections are opened at import time.
"""

from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

# Module-level placeholders — lazily initialised on first use.
_engine: Any = None
_SessionLocal: sessionmaker[Session] | None = None


def _init_engine() -> None:
    """Create engine and session factory once, on first call."""
    global _engine, _SessionLocal
    if _engine is not None:
        return
    settings = get_settings()
    connect_args: dict[str, Any] = {}
    if settings.DATABASE_URL.startswith("postgresql+psycopg"):
        connect_args["prepare_threshold"] = None
    _engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        echo=(settings.APP_ENV == "development"),
        hide_parameters=True,
        connect_args=connect_args,
    )
    _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def get_engine() -> Any:
    """Return the SQLAlchemy engine, creating it if necessary."""
    _init_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the session factory, creating it if necessary."""
    _init_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session and ensures cleanup."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
