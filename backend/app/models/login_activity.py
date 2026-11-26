"""Informational login activity records for security monitoring."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LoginActivity(Base):
    __tablename__ = "login_activities"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    attempted_identifier: Mapped[str | None] = mapped_column(String(320), nullable=True)
    browser_name: Mapped[str] = mapped_column(String(64), nullable=False, default="Unknown")
    browser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    operating_system: Mapped[str] = mapped_column(String(64), nullable=False, default="Unknown")
    os_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    device_type: Mapped[str] = mapped_column(String(24), nullable=False, default="Unknown")
    login_status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint("login_status IN ('success', 'failed')", name="ck_login_activities_status"),
        Index("ix_login_activities_attempted_at", "attempted_at"),
        Index("ix_login_activities_user_id", "user_id"),
        Index("ix_login_activities_browser_name", "browser_name"),
        Index("ix_login_activities_login_status", "login_status"),
        Index("ix_login_activities_attempted_identifier", "attempted_identifier"),
    )
