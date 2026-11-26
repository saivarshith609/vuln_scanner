"""
VulnScanner API — Pydantic schemas registry.

Re-exports all request and response schemas for Asset, Scan, Vulnerability,
Dashboard, and common pagination structures.
"""

from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetType,
    AssetUpdate,
)
from app.schemas.common import PaginatedResponse
from app.schemas.dashboard import DashboardResponse, SeverityCounts
from app.schemas.scan import (
    Progress,
    ScanAuthorizationMode,
    ScanCreate,
    ScanResponse,
    ScanStatus,
    ScanType,
    ScanUpdate,
)
from app.schemas.report import (
    FindingsSummary,
    ReportCreate,
    ReportDetailResponse,
    ReportResponse,
)
from app.schemas.vulnerability import (
    CvssScore,
    Severity,
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityStatus,
    VulnerabilityUpdate,
)

__all__ = [
    # Common
    "PaginatedResponse",
    # Asset
    "AssetType",
    "AssetCreate",
    "AssetUpdate",
    "AssetResponse",
    # Scan
    "ScanType",
    "ScanStatus",
    "ScanAuthorizationMode",
    "Progress",
    "ScanCreate",
    "ScanUpdate",
    "ScanResponse",
    # Report
    "FindingsSummary",
    "ReportCreate",
    "ReportResponse",
    "ReportDetailResponse",
    # Vulnerability
    "Severity",
    "VulnerabilityStatus",
    "CvssScore",
    "VulnerabilityCreate",
    "VulnerabilityUpdate",
    "VulnerabilityResponse",
    # Dashboard
    "SeverityCounts",
    "DashboardResponse",
]
