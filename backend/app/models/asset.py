"""
VulnScanner API — Asset ORM model.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    """A network asset registered for vulnerability scanning."""

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────────────
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="asset", lazy="selectin",
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(  # noqa: F821
        "Vulnerability", back_populates="asset", lazy="selectin",
    )

    __table_args__ = (
        Index("ix_assets_name", "name"),
        Index("ix_assets_asset_type", "asset_type"),
        Index("ix_assets_owner_user_id", "owner_user_id"),
    )

    def __repr__(self) -> str:
        return f"<Asset id={self.id} name={self.name!r}>"
