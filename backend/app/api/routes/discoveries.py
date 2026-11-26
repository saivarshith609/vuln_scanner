"""Authenticated, bounded Nmap host discovery and inventory endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.core.audit import add_audit_event
from app.core.config import get_settings
from app.db.session import get_db, get_session_factory
from app.models.platform_setting import PlatformSetting
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.scanner.auth_service import (
    OnDemandAuthorizationRequiredError,
    TargetNotAuthorizedError,
    normalize_discovery_cidr,
    normalize_ip_range,
    target_is_authorized,
    target_is_within_discovery_scope,
    validate_on_demand_discovery_authorization,
    validate_range_authorized,
    validate_target_authorized,
)
from app.scanner.nmap_service import scanner_service
from app.scanner.service import NmapNotAvailableError
from app.schemas.common import PaginatedResponse
from app.schemas.discovery import DiscoveryCreate, DiscoveredHostResponse, DiscoveryResponse, DiscoveryTargetType

router = APIRouter()
logger = logging.getLogger(__name__)


def _owned_discovery(db: Session, discovery_id: uuid.UUID, operator: AuthenticatedOperator) -> Scan:
    discovery = db.get(Scan, discovery_id)
    if discovery is None or discovery.operation != "discovery":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found.")
    require_owner(operator, discovery.owner_user_id)
    return discovery


@router.get("", response_model=PaginatedResponse[DiscoveryResponse])
def list_discoveries(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[DiscoveryResponse]:
    query = select(Scan).where(Scan.operation == "discovery")
    if not operator.is_admin:
        query = query.where(Scan.owner_user_id == operator.user_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(Scan.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create(
        items=[DiscoveryResponse.model_validate(item) for item in items],
        total=total, page=page, size=size,
    )


@router.post("", response_model=DiscoveryResponse, status_code=status.HTTP_201_CREATED)
def create_discovery(
    payload: DiscoveryCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> DiscoveryResponse:
    requested_scope = payload.cidr if payload.target_type == DiscoveryTargetType.cidr else f"{payload.start_ip}-{payload.end_ip}"
    if not payload.authorization_confirmed:
        logger.warning(
            "Discovery authorization rejected owner_user_id=%s requested_scope=%r "
            "authorization_mode=%s error=missing_confirmation",
            operator.user_id, requested_scope, payload.authorization_mode.value,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Confirm that you own this network scope or have explicit permission to discover hosts within it.",
        )

    settings = get_settings()
    try:
        if payload.authorization_mode.value == "on_demand":
            validate_on_demand_discovery_authorization(payload.authorization_confirmed)
        if payload.target_type == DiscoveryTargetType.cidr:
            target, _count = normalize_discovery_cidr(payload.cidr or "", settings.DISCOVERY_MAX_ADDRESSES)
            if payload.authorization_mode.value == "allow_list":
                validate_target_authorized(target, db, operator.user_id, operator.is_admin)
            target_args = [target]
            range_start = range_end = None
        else:
            target, range_start, range_end, _count, target_args = normalize_ip_range(
                payload.start_ip or "", payload.end_ip or "", settings.DISCOVERY_MAX_ADDRESSES,
            )
            if payload.authorization_mode.value == "allow_list":
                validate_range_authorized(range_start, range_end, db, operator.user_id, operator.is_admin)
    except ValueError as exc:
        logger.warning(
            "Discovery validation rejected owner_user_id=%s requested_scope=%r "
            "authorization_mode=%s error=%s",
            operator.user_id, requested_scope, payload.authorization_mode.value, exc,
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except TargetNotAuthorizedError as exc:
        logger.warning(
            "Discovery authorization rejected owner_user_id=%s requested_scope=%r "
            "authorization_mode=%s error=%s",
            operator.user_id, requested_scope, payload.authorization_mode.value, exc,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except OnDemandAuthorizationRequiredError as exc:
        logger.warning(
            "Discovery authorization rejected owner_user_id=%s requested_scope=%r "
            "authorization_mode=%s error=%s",
            operator.user_id, requested_scope, payload.authorization_mode.value, exc,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    try:
        scanner_service._build_args(target, "network", target_args=target_args)
    except NmapNotAvailableError as exc:
        logger.error(
            "Discovery scanner unavailable owner_user_id=%s target=%r authorization_mode=%s error=%s",
            operator.user_id, target, payload.authorization_mode.value, exc,
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Scanner not available: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    confirmation_time = datetime.now(timezone.utc)
    discovery = Scan(
        id=uuid.uuid4(), owner_user_id=operator.user_id, target=target,
        operation="discovery", target_kind=payload.target_type.value,
        range_start=range_start, range_end=range_end,
        authorization_mode=payload.authorization_mode.value,
        authorization_confirmed=payload.authorization_confirmed,
        authorization_confirmed_at=confirmation_time,
        partial_results=False, scan_type="network", status="queued", progress=0,
        created_at=confirmation_time,
    )
    db.add(discovery)
    add_audit_event(
        db, "discovery.requested", actor_user_id=operator.user_id,
        resource_type="discovery", resource_id=discovery.id,
        metadata={"scope": target, "authorization_mode": discovery.authorization_mode, "target_kind": discovery.target_kind},
    )
    db.commit()
    db.refresh(discovery)
    logger.info(
        "Discovery %s queued owner_user_id=%s target=%r target_kind=%s "
        "profile=network authorization_mode=%s confirmed_at=%s auth_method=%s",
        discovery.id, operator.user_id, target, payload.target_type.value,
        payload.authorization_mode.value, confirmation_time.isoformat(),
        operator.method,
    )

    platform = db.get(PlatformSetting, 1)
    max_concurrent = platform.max_concurrent_scans if platform else settings.NMAP_MAX_CONCURRENT
    rate_limit = platform.scanner_rate_limit_per_minute if platform else 100
    discovery_id = discovery.id

    def _launch() -> None:
        try:
            scanner_service.launch(
                discovery_id, target, "network",
                scan_timeout_seconds=settings.DISCOVERY_TIMEOUT_SECONDS,
                max_concurrent=max_concurrent,
                rate_limit_per_minute=rate_limit,
                target_args=target_args,
                recheck_authorization=True,
            )
        except Exception as exc:
            failure_db = get_session_factory()()
            try:
                failed = failure_db.get(Scan, discovery_id)
                if failed:
                    failed.status = "failed"
                    failed.error_message = f"Failed to launch network discovery: {exc}"
                    failed.completed_at = datetime.now(timezone.utc)
                    failure_db.commit()
                    logger.error(
                        "Discovery %s launch failed target=%r authorization_mode=%s error=%s",
                        discovery_id, target, failed.authorization_mode, exc,
                    )
            finally:
                failure_db.close()

    background_tasks.add_task(_launch)
    return DiscoveryResponse.model_validate(discovery)


@router.get("/{discovery_id}", response_model=DiscoveryResponse)
def get_discovery(
    discovery_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> DiscoveryResponse:
    return DiscoveryResponse.model_validate(_owned_discovery(db, discovery_id, operator))


@router.get("/{discovery_id}/hosts", response_model=PaginatedResponse[DiscoveredHostResponse])
def list_discovered_hosts(
    discovery_id: uuid.UUID,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=500),
    search: str | None = Query(None, max_length=255),
    authorization: str = Query("all", pattern="^(all|authorized|unauthorized)$"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[DiscoveredHostResponse]:
    discovery = _owned_discovery(db, discovery_id, operator)
    query = select(ScanResult).where(ScanResult.scan_id == discovery_id, ScanResult.port.is_(None))
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            ScanResult.host_address.ilike(term) | ScanResult.hostname.ilike(term) |
            ScanResult.mac_address.ilike(term) | ScanResult.vendor.ilike(term)
        )
    rows = db.scalars(query.order_by(ScanResult.created_at.desc())).all()
    unique: dict[str, ScanResult] = {}
    for row in rows:
        unique.setdefault(row.host_address, row)

    inventory: list[DiscoveredHostResponse] = []
    for row in unique.values():
        authorized = target_is_authorized(row.host_address, db, operator.user_id, operator.is_admin)
        if (
            not authorized
            and discovery.authorization_mode == "on_demand"
            and discovery.authorization_confirmed
        ):
            authorized = target_is_within_discovery_scope(
                row.host_address,
                discovery.target_kind,
                discovery.target,
                discovery.range_start,
                discovery.range_end,
            )
        if authorization == "authorized" and not authorized:
            continue
        if authorization == "unauthorized" and authorized:
            continue
        inventory.append(DiscoveredHostResponse(
            id=row.id, discovery_id=discovery_id, ip_address=row.host_address,
            hostname=row.hostname, mac_address=row.mac_address, vendor=row.vendor,
            discovery_status="responding" if row.host_state == "up" else "observed",
            last_seen_at=row.created_at, authorized=authorized,
        ))
    total = len(inventory)
    start = (page - 1) * size
    return PaginatedResponse.create(items=inventory[start:start + size], total=total, page=page, size=size)


@router.post("/{discovery_id}/cancel", response_model=DiscoveryResponse)
def cancel_discovery(
    discovery_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> DiscoveryResponse:
    discovery = _owned_discovery(db, discovery_id, operator)
    if discovery.status in {"completed", "failed"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel discovery with status '{discovery.status}'.")
    scanner_service.cancel(discovery.id)
    if scanner_service.get_job(discovery.id) is None:
        discovery.status = "cancelled"
        discovery.error_message = "Cancelled by operator. A non-response is not proof that undiscovered hosts are offline."
        discovery.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(discovery)
    return DiscoveryResponse.model_validate(discovery)
