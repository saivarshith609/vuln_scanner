"""
VulnScanner API — Dashboard Pydantic schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.scan import ScanResponse
from app.schemas.vulnerability import VulnerabilityResponse


class SeverityCounts(BaseModel):
    """Vulnerability count breakdown by severity."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)


class DashboardResponse(BaseModel):
    """Aggregated dashboard telemetry and recent activity."""

    total_assets: int = Field(default=0, ge=0)
    discovered_hosts: int = Field(default=0, ge=0)
    active_scans: int = Field(default=0, ge=0)
    total_scans: int = Field(default=0, ge=0)
    completed_scans: int = Field(default=0, ge=0)
    failed_scans: int = Field(default=0, ge=0)
    cancelled_scans: int = Field(default=0, ge=0)
    total_vulnerabilities: int = Field(default=0, ge=0)
    resolved_vulnerabilities: int = Field(default=0, ge=0)
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)
    recent_scans: list[ScanResponse] = Field(default_factory=list)
    recent_vulnerabilities: list[VulnerabilityResponse] = Field(default_factory=list)
