"""
VulnScanner API — Security Report ORM model (Phase 9.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Report(Base):
    """A persisted security assessment report with execution metadata and posture snapshot."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True,
    )
    report_code: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    report_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="executive",
    )
    format: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pdf",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="ready",
    )
    scan_date: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    date_from: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    date_to: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    file_size: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="1.2 MB",
    )
    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    info_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    total_findings: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    security_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    total_assets: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    total_scans: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    snapshot_data: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_reports_name", "name"),
        Index("ix_reports_report_type", "report_type"),
        Index("ix_reports_created_at", "created_at"),
        Index("ix_reports_report_code", "report_code"),
        Index("ix_reports_owner_user_id", "owner_user_id"),
        Index("ix_reports_scan_id", "scan_id"),
    )

    def __repr__(self) -> str:
        return f"<Report id={self.id} name={self.name!r} type={self.report_type!r} status={self.status!r}>"
