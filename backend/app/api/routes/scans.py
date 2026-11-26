"""
VulnScanner API — Scan management endpoints (Phase 4.2).

Changes from Phase 3:
- POST /api/v1/scans validates either a persistent authorized-target scope or
  an explicitly confirmed single-target on-demand request before persistence.
- POST /api/v1/scans dispatches a background Task via NmapScannerService
  when authorization passes.
- POST /api/v1/scans/{id}/cancel now terminates the real Nmap subprocess.
- ScanResponse includes error_message for failed/cancelled scans.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.audit import add_audit_event
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.platform_setting import PlatformSetting
from app.scanner.auth_service import (
    OnDemandAuthorizationRequiredError,
    TargetNotAuthorizedError,
    validate_on_demand_target,
    validate_target_authorized,
)
from app.scanner.nmap_service import scanner_service
from app.scanner.service import NmapNotAvailableError
from app.schemas.common import PaginatedResponse
from app.schemas.scan import ScanCreate, ScanResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "",
    response_model=PaginatedResponse[ScanResponse],
    summary="List scans",
    description="Retrieve a paginated scan history with optional filtering.",
)
def list_scans(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    scan_type: str | None = Query(None, description="Filter by scan type"),
    target: str | None = Query(None, description="Filter by target"),
    asset_id: uuid.UUID | None = Query(None, description="Filter by asset ID"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[ScanResponse]:
    query = select(Scan)
    if not operator.is_admin:
        query = query.where(Scan.owner_user_id == operator.user_id)

    if status_filter:
        query = query.where(Scan.status == status_filter.strip().lower())
    if scan_type:
        query = query.where(Scan.scan_type == scan_type.strip().lower())
    if target:
        query = query.where(Scan.target.ilike(f"%{target.strip()}%"))
    if asset_id:
        query = query.where(Scan.asset_id == asset_id)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    offset = (page - 1) * size
    items = db.scalars(
        query.order_by(Scan.created_at.desc()).offset(offset).limit(size)
    ).all()

    return PaginatedResponse.create(
        items=[ScanResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scan",
    description=(
        "Validate either persistent allow-list authorization or an explicit "
        "single-target on-demand confirmation, create a scan record, and launch "
        "the Nmap background task."
    ),
)
def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ScanResponse:
    # ── 1. Validate target syntax and authorization ────────────────────────
    try:
        if scan_in.authorization_mode.value == "on_demand":
            validated_target = validate_on_demand_target(
                scan_in.target,
                scan_in.authorization_confirmed,
            )
        else:
            validated_target = validate_target_authorized(scan_in.target, db, operator.user_id, operator.is_admin)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except TargetNotAuthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except OnDemandAuthorizationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    if "/" in validated_target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "CIDR targets are network-discovery scopes, not individual scan targets. "
                "Use POST /api/v1/discoveries with the network profile."
            ),
        )

    # ── 2. Validate scan type ─────────────────────────────────────────────
    from app.scanner.nmap_service import _SCAN_PROFILES
    if scan_in.scan_type.value not in _SCAN_PROFILES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported scan type {scan_in.scan_type.value!r}.",
        )

    # ── 3. Validate asset reference or auto-associate by target ───────────
    matched_asset_id = scan_in.asset_id
    if matched_asset_id:
        asset = db.get(Asset, matched_asset_id)
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID '{matched_asset_id}' not found",
            )
        require_owner(operator, asset.owner_user_id)
    else:
        asset_query = select(Asset).where(func.lower(Asset.target) == validated_target.lower())
        if not operator.is_admin:
            asset_query = asset_query.where(Asset.owner_user_id == operator.user_id)
        existing_asset = db.scalar(asset_query)
        if existing_asset:
            matched_asset_id = existing_asset.id

    # ── 4. Check Nmap availability ────────────────────────────────────────
    try:
        scanner_service._build_args(validated_target, scan_in.scan_type.value)
    except NmapNotAvailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Scanner not available: {exc}",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # ── 5. Persist scan record in 'queued' state ──────────────────────────
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid.uuid4(),
        owner_user_id=operator.user_id,
        asset_id=matched_asset_id,
        target=validated_target,
        operation="scan",
        target_kind="host",
        authorization_mode=scan_in.authorization_mode.value,
        authorization_confirmed=scan_in.authorization_confirmed,
        authorization_confirmed_at=now if scan_in.authorization_confirmed else None,
        scan_type=scan_in.scan_type.value,
        status="queued",
        progress=0,
        created_at=now,
        started_at=None,
        completed_at=None,
    )
    db.add(scan)
    add_audit_event(
        db, "scan.created", actor_user_id=operator.user_id,
        resource_type="scan", resource_id=scan.id,
        metadata={"target": validated_target, "profile": scan.scan_type, "authorization_mode": scan.authorization_mode},
    )
    db.commit()
    db.refresh(scan)
    logger.info(
        "Scan %s queued owner_user_id=%s target=%r profile=%s authorization_mode=%s "
        "confirmed_at=%s auth_method=%s",
        scan.id,
        operator.user_id,
        validated_target,
        scan.scan_type,
        scan_in.authorization_mode.value,
        scan.authorization_confirmed_at.isoformat() if scan.authorization_confirmed_at else None,
        operator.method,
    )

    # ── 6. Launch background Nmap task ────────────────────────────────────
    scan_id_copy = scan.id
    scan_type_copy = scan.scan_type
    platform_settings = db.get(PlatformSetting, 1)
    runtime_settings = get_settings()
    max_concurrent = (
        platform_settings.max_concurrent_scans
        if platform_settings is not None
        else runtime_settings.NMAP_MAX_CONCURRENT
    )
    rate_limit_per_minute = (
        platform_settings.scanner_rate_limit_per_minute
        if platform_settings is not None
        else 100
    )

    def _launch() -> None:
        """Schedule the scanner task from this background task."""
        try:
            scanner_service.launch(
                scan_id=scan_id_copy,
                target=validated_target,
                scan_type=scan_type_copy,
                max_concurrent=max_concurrent,
                rate_limit_per_minute=rate_limit_per_minute,
                recheck_authorization=True,
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "Failed to launch scan %s: %s", scan_id_copy, exc
            )

    background_tasks.add_task(_launch)

    return ScanResponse.model_validate(scan)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan by ID",
)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ScanResponse:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )
    require_owner(operator, scan.owner_user_id)
    return ScanResponse.model_validate(scan)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel scan",
    description=(
        "Cancel a queued or running scan.  "
        "For running scans, terminates the Nmap subprocess and waits for "
        "confirmed termination before marking the scan cancelled."
    ),
)
def cancel_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ScanResponse:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )
    require_owner(operator, scan.owner_user_id)

    if scan.status == "cancelled":
        return ScanResponse.model_validate(scan)

    if scan.status in ("completed", "failed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status '{scan.status}'",
        )

    # Signal the running asyncio task (if any) to cancel
    scanner_service.cancel(scan_id)

    # For queued scans with no running task, mark cancelled immediately
    job = scanner_service.get_job(scan_id)
    if job is None:
        scan.status = "cancelled"
        scan.error_message = "Cancelled by operator."
        scan.completed_at = datetime.now(timezone.utc)
        add_audit_event(db, "scan.cancelled", actor_user_id=operator.user_id, resource_type="scan", resource_id=scan.id)
        db.commit()
        db.refresh(scan)

    # For running scans the background task will update DB asynchronously;
    # return the current state (the client should poll)
    db.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete scan",
    description=(
        "Permanently delete a scan and its associated scan results. "
        "Actively running scans must be aborted or cancelled before deletion."
    ),
)
def delete_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )
    require_owner(operator, scan.owner_user_id)

    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete an actively running scan. Abort the scan first.",
        )

    # Clean up any queued task handle before removal
    scanner_service.cancel(scan_id)

    db.delete(scan)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
