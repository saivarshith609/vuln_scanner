"""
VulnScanner API — Vulnerability management endpoints.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.common import PaginatedResponse
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[VulnerabilityResponse],
    summary="List vulnerabilities",
    description="Retrieve a paginated list of vulnerabilities with filters for severity, status, CVE, asset, or scan.",
)
def list_vulnerabilities(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status (open, in_progress, resolved, false_positive, accepted)"),
    cve_id: str | None = Query(None, description="Filter by CVE identifier"),
    asset_id: uuid.UUID | None = Query(None, description="Filter by asset UUID"),
    scan_id: uuid.UUID | None = Query(None, description="Filter by scan UUID"),
    search: str | None = Query(None, description="Search term for title, description, or CVE ID"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[VulnerabilityResponse]:
    query = select(Vulnerability).join(Scan, Vulnerability.scan_id == Scan.id).options(joinedload(Vulnerability.asset))
    if not operator.is_admin:
        query = query.where(Scan.owner_user_id == operator.user_id)

    if severity:
        query = query.where(Vulnerability.severity == severity.strip().lower())

    if status_filter:
        query = query.where(Vulnerability.status == status_filter.strip().lower())

    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id.strip()}%"))

    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)

    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)

    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                Vulnerability.title.ilike(term),
                Vulnerability.description.ilike(term),
                Vulnerability.cve_id.ilike(term),
            )
        )

    # Count
    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.scalar(count_stmt) or 0

    # Paginate by newest first
    offset = (page - 1) * size
    stmt = query.order_by(Vulnerability.created_at.desc()).offset(offset).limit(size)
    items = db.scalars(stmt).all()

    validated_items = [VulnerabilityResponse.model_validate(item) for item in items]
    return PaginatedResponse.create(
        items=validated_items,
        total=total,
        page=page,
        size=size,
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
    summary="Get vulnerability by ID",
    description="Retrieve details of a single vulnerability finding by UUID.",
)
def get_vulnerability(
    vulnerability_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> VulnerabilityResponse:
    stmt = (
        select(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    vuln = db.scalar(stmt)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID '{vulnerability_id}' not found",
        )
    require_owner(operator, db.get(Scan, vuln.scan_id).owner_user_id)
    return VulnerabilityResponse.model_validate(vuln)


@router.patch(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
    summary="Update vulnerability",
    description="Update vulnerability triage status, severity, or remediation notes.",
)
def update_vulnerability(
    vulnerability_id: uuid.UUID,
    vuln_in: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> VulnerabilityResponse:
    stmt = (
        select(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    vuln = db.scalar(stmt)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID '{vulnerability_id}' not found",
        )
    require_owner(operator, db.get(Scan, vuln.scan_id).owner_user_id)

    update_data = vuln_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field in ("severity", "status") and value is not None:
            setattr(vuln, field, value.value if hasattr(value, "value") else str(value))
        elif value is not None and isinstance(value, str):
            setattr(vuln, field, value.strip())
        else:
            setattr(vuln, field, value)

    db.commit()

    refreshed_stmt = (
        select(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    refreshed_vuln = db.scalar(refreshed_stmt)
    return VulnerabilityResponse.model_validate(refreshed_vuln)
