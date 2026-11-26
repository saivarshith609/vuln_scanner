"""Persisted Phase 10 platform preferences and secret metadata."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PlatformSetting(Base):
    """Singleton row containing database-managed operator preferences."""

    __tablename__ = "platform_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    scanner_rate_limit_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    accent_color: Mapped[str] = mapped_column(String(7), nullable=False, default="#3b82f6")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class IntegrationCredential(Base):
    """Encrypted write-only credential for a README-supported integration."""

    __tablename__ = "integration_credentials"

    provider: Mapped[str] = mapped_column(String(20), primary_key=True)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    masked_hint: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class PlatformApiKey(Base):
    """Singleton platform API-key verifier; the raw key is never persisted."""

    __tablename__ = "platform_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    hash_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    masked_hint: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class OperatorSession(Base):
    """Server-tracked single-operator session; raw bearer tokens are never stored."""

    __tablename__ = "operator_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True,
    )
    csrf_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_operator_sessions_expires_at", "expires_at"),
        Index("ix_operator_sessions_revoked_at", "revoked_at"),
        Index("ix_operator_sessions_user_id", "user_id"),
    )
