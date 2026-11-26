"""
VulnScanner API — Scan ORM model.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    """A vulnerability scan run against a target."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    operation: Mapped[str] = mapped_column(String(20), nullable=False, default="scan")
    target_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="host")
    range_start: Mapped[str | None] = mapped_column(String(45), nullable=True)
    range_end: Mapped[str | None] = mapped_column(String(45), nullable=True)
    authorization_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="allow_list")
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    partial_results: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued",
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Non-empty when status is 'failed' or 'cancelled' — safe user-facing error."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────────────
    asset: Mapped["Asset | None"] = relationship(  # noqa: F821
        "Asset", back_populates="scans",
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(  # noqa: F821
        "Vulnerability",
        back_populates="scan",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    results: Mapped[list["ScanResult"]] = relationship(  # noqa: F821
        "ScanResult",
        back_populates="scan",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_scans_progress"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_scans_status",
        ),
        CheckConstraint("operation IN ('scan', 'discovery')", name="ck_scans_operation"),
        CheckConstraint("target_kind IN ('host', 'cidr', 'range')", name="ck_scans_target_kind"),
        CheckConstraint(
            "authorization_mode IN ('allow_list', 'on_demand')",
            name="ck_scans_authorization_mode",
        ),
        Index("ix_scans_status", "status"),
        Index("ix_scans_operation", "operation"),
        Index("ix_scans_asset_id", "asset_id"),
        Index("ix_scans_owner_user_id", "owner_user_id"),
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target!r} status={self.status!r}>"
