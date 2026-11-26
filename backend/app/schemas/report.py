"""
VulnScanner API — Report schemas (Phase 9.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class FindingsSummary(BaseModel):
    """Vulnerability severity breakdown."""

    model_config = ConfigDict(from_attributes=True)

    critical: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    low: int = Field(0, ge=0)
    info: int = Field(0, ge=0)
    total: int = Field(0, ge=0)


class ReportCreate(BaseModel):
    """Payload to generate and persist a new security report."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Name or title of the report",
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Target scope for the report (e.g. asset, subnet, or all)",
    )
    report_type: str = Field(
        "executive",
        pattern="^(executive|technical|compliance|network|delta)$",
        description="Report classification type",
    )
    format: str = Field(
        "pdf",
        pattern="^(pdf|csv|json|PDF|CSV|JSON)$",
        description="Primary export format requested",
    )
    date_from: str | None = Field(
        None,
        description="Start date for the report scope (YYYY-MM-DD)",
    )
    date_to: str | None = Field(
        None,
        description="End date for the report scope (YYYY-MM-DD)",
    )


class ReportResponse(BaseModel):
    """Summary of a saved security report (used in lists and cards)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_code: str | None = None
    name: str
    target: str
    report_type: str
    format: str
    status: str
    scan_date: str
    date_from: str | None = None
    date_to: str | None = None
    file_size: str
    findings_summary: FindingsSummary
    security_score: int | None = None
    total_assets: int = 0
    total_scans: int = 0
    created_at: datetime
    updated_at: datetime
    download_url: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def type(self) -> str:
        """Alias for report_type to match existing frontend interface."""
        return self.report_type


class ReportDetailResponse(ReportResponse):
    """Full detail of a saved security report, including findings snapshot."""

    snapshot_data: dict[str, Any] | list[Any] | None = None


class ScanReportPort(BaseModel):
    """A persisted host/port observation included in a scan report."""

    id: uuid.UUID
    host_address: str
    hostname: str | None = None
    host_state: str
    port: int | None = None
    protocol: str | None = None
    state: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_information: str | None = None


class ScanReportFinding(BaseModel):
    """An actual vulnerability record linked to the selected scan."""

    id: uuid.UUID
    title: str
    severity: str
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_target: str
    port: int | None = None
    service_name: str | None = None
    description: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    status: str


class ScanReportSummary(BaseModel):
    """Counts derived only from persisted records; unknown metrics remain null."""

    total_ports_examined: int | None = None
    recorded_port_entries: int = 0
    open_ports: int = 0
    closed_or_filtered_ports: int = 0
    identified_services: int = 0
    findings: FindingsSummary


class ScanReportDetail(BaseModel):
    """Shared source of truth for the in-app and PDF scan reports."""

    scan_id: uuid.UUID
    target: str
    status: str
    progress: int
    scan_profile: str
    scanner: str = "Nmap"
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: int | None = None
    error_message: str | None = None
    resolved_addresses: list[str] = Field(default_factory=list)
    authorization_mode: str | None = None
    recorded_configuration: str | None = None
    port_inventory_recorded: bool = False
    summary: ScanReportSummary
    ports: list[ScanReportPort] = Field(default_factory=list)
    findings: list[ScanReportFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
