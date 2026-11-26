"""
VulnScanner API — Scan result retrieval endpoints.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.schemas.common import PaginatedResponse
from app.schemas.scan_result import ScanResultResponse

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[ScanResultResponse],
    summary="List scan results",
    description=(
        "Return paginated host/port/service discovery results for a specific scan. "
        "These are raw Nmap observations — not vulnerability records."
    ),
)
def list_scan_results(
    scan_id: uuid.UUID | None = Query(None, description="UUID of the scan"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    host: str | None = Query(None, description="Filter by host address"),
    port_state: str | None = Query(None, description="Filter by port state (open, closed, filtered)"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[ScanResultResponse]:
    if scan_id is None and not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'scan_id' or 'host' must be specified.",
        )

    query = select(ScanResult).join(Scan, ScanResult.scan_id == Scan.id)
    if not operator.is_admin:
        query = query.where(Scan.owner_user_id == operator.user_id)

    if scan_id is not None:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan '{scan_id}' not found.",
            )
        require_owner(operator, scan.owner_user_id)
        query = query.where(ScanResult.scan_id == scan_id)

    if host:
        query = query.where(ScanResult.host_address == host.strip())
    if port_state:
        query = query.where(ScanResult.port_state == port_state.strip().lower())

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    offset = (page - 1) * size
    items = db.scalars(
        query.order_by(ScanResult.created_at.desc(), ScanResult.host_address, ScanResult.port).offset(offset).limit(size)
    ).all()

    return PaginatedResponse.create(
        items=[ScanResultResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
    )
