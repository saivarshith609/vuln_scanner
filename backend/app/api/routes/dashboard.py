"""
VulnScanner API — Dashboard aggregated telemetry endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.scan_result import ScanResult
from app.schemas.dashboard import DashboardResponse, SeverityCounts
from app.schemas.scan import ScanResponse
from app.schemas.vulnerability import VulnerabilityResponse


router = APIRouter()


@router.get(
    "",
    response_model=DashboardResponse,
    summary="Dashboard telemetry",
    description="Retrieve aggregated system metrics, severity breakdown, and recent activity from live database records.",
)
def get_dashboard(
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> DashboardResponse:
    scan_scope = True if operator.is_admin else Scan.owner_user_id == operator.user_id
    asset_scope = True if operator.is_admin else Asset.owner_user_id == operator.user_id
    # 1. Total counts
    total_assets = db.scalar(select(func.count(Asset.id)).where(asset_scope)) or 0
    discovered_hosts = db.scalar(
        select(func.count(func.distinct(ScanResult.host_address))).join(Scan).where(
            ScanResult.host_state == "up", scan_scope,
        )
    ) or 0
    total_scans = db.scalar(select(func.count(Scan.id)).where(scan_scope)) or 0
    active_scans = (
        db.scalar(
            select(func.count(Scan.id)).where(scan_scope, Scan.status.in_(["running", "queued"]))
        )
        or 0
    )
    completed_scans = db.scalar(select(func.count(Scan.id)).where(scan_scope, Scan.status == "completed")) or 0
    failed_scans = db.scalar(select(func.count(Scan.id)).where(scan_scope, Scan.status == "failed")) or 0
    cancelled_scans = db.scalar(select(func.count(Scan.id)).where(scan_scope, Scan.status == "cancelled")) or 0
    total_vulnerabilities = db.scalar(select(func.count(Vulnerability.id)).join(Scan).where(scan_scope)) or 0
    resolved_vulnerabilities = db.scalar(
        select(func.count(Vulnerability.id)).join(Scan).where(scan_scope, Vulnerability.status == "resolved")
    ) or 0

    # 2. Severity distribution
    sev_rows = db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id)).join(Scan).where(scan_scope).group_by(
            Vulnerability.severity
        )
    ).all()
    sev_map = {row[0]: row[1] for row in sev_rows}
    severity_counts = SeverityCounts(
        critical=sev_map.get("critical", 0),
        high=sev_map.get("high", 0),
        medium=sev_map.get("medium", 0),
        low=sev_map.get("low", 0),
        info=sev_map.get("info", 0),
    )

    # 3. Recent scans (up to 5, latest first)
    recent_scans_entities = db.scalars(
        select(Scan).where(scan_scope).order_by(Scan.created_at.desc()).limit(5)
    ).all()
    recent_scans = [
        ScanResponse.model_validate(scan) for scan in recent_scans_entities
    ]

    # 4. Recent vulnerabilities (up to 5, latest first)
    recent_vulns_entities = db.scalars(
        select(Vulnerability)
        .join(Scan)
        .where(scan_scope)
        .options(joinedload(Vulnerability.asset))
        .order_by(Vulnerability.created_at.desc())
        .limit(5)
    ).all()
    recent_vulns = [
        VulnerabilityResponse.model_validate(vuln)
        for vuln in recent_vulns_entities
    ]


    return DashboardResponse(
        total_assets=total_assets,
        discovered_hosts=discovered_hosts,
        active_scans=active_scans,
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        cancelled_scans=cancelled_scans,
        total_vulnerabilities=total_vulnerabilities,
        resolved_vulnerabilities=resolved_vulnerabilities,
        severity_counts=severity_counts,
        recent_scans=recent_scans,
        recent_vulnerabilities=recent_vulns,
    )
