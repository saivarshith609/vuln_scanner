"""
VulnScanner — AuthorizedTarget ORM model.

Represents an explicitly approved scan target (IP address, CIDR range,
or hostname).  Only targets with a matching, enabled entry in this table
may be scanned.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthorizedTarget(Base):
    """An explicitly authorized scan target entry."""

    __tablename__ = "authorized_targets"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    """Normalized IP address, CIDR range, or hostname."""

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Authorization notes / justification."""

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    """When False, target is administratively disabled without deletion."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )

    __table_args__ = (
        Index("ix_authorized_targets_target", "target"),
        Index("ix_authorized_targets_enabled", "is_enabled"),
        Index("ix_authorized_targets_owner_user_id", "owner_user_id"),
        Index(
            "uq_authorized_targets_owner_target",
            "owner_user_id",
            "target",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
    )

    def __repr__(self) -> str:
        return f"<AuthorizedTarget id={self.id} target={self.target!r} enabled={self.is_enabled}>"
