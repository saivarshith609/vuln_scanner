"""
VulnScanner — ScanResult ORM model.

Stores actual host/port/service discovery findings produced by Nmap.
This is NOT a vulnerability record — it is raw discovery data.
Vulnerability records are only created when a concrete, confirmed
vulnerability has been identified (not implemented in Phase 4.2).
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanResult(Base):
    """
    A single discovered host/port/service entry from an Nmap scan.

    Data-integrity guarantee: open ports and identified service versions
    are NOT automatically treated as vulnerabilities.  This model records
    what Nmap observed — no CVE or CVSS data is synthesized.
    """

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
    )

    # ── Host information ──────────────────────────────────────────────────
    host_address: Mapped[str] = mapped_column(String(255), nullable=False)
    """IP address of the discovered host."""

    host_state: Mapped[str] = mapped_column(String(20), nullable=False, default="up")
    """Host state as reported by Nmap: 'up' or 'down'."""

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Reverse-DNS hostname if Nmap resolved one."""

    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    """MAC address when Nmap can observe it, usually on a local segment."""

    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Vendor reported by Nmap for the observed MAC address, when available."""

    # ── Port / service information ────────────────────────────────────────
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    """TCP/UDP port number, NULL for host-only discovery records."""

    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    """'tcp' or 'udp'."""

    port_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    """Port state: 'open', 'closed', 'filtered', etc."""

    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    """IANA service name (e.g. 'http', 'ssh', 'ftp')."""

    service_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    """Software product name (e.g. 'Apache httpd', 'OpenSSH')."""

    service_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    """Software version string."""

    service_extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    """Additional service detail string from Nmap."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────
    scan: Mapped["Scan"] = relationship(  # noqa: F821
        "Scan", back_populates="results",
    )

    __table_args__ = (
        Index("ix_scan_results_scan_id", "scan_id"),
        Index("ix_scan_results_host_address", "host_address"),
        Index("ix_scan_results_port", "port"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanResult id={self.id} host={self.host_address!r} "
            f"port={self.port} state={self.port_state!r}>"
        )
