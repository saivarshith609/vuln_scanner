"""Protected administrator control-center APIs."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import add_audit_event
from app.core.auth import AuthenticatedOperator, require_admin, revoke_user_sessions
from app.core.passwords import hash_password
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.platform_setting import OperatorSession
from app.models.report import Report
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.scanner.nmap_service import scanner_service
from app.schemas.admin import (
    AdminActionResponse,
    AdminDiscoverySummary,
    AdminHealth,
    AdminOverview,
    AdminPasswordResetRequest,
    AdminReportSummary,
    AdminScanSummary,
    AdminSessionSummary,
    AdminUserDetail,
    AdminUserSummary,
    AdminUserUpdate,
    AdminVulnerabilitySummary,
    AuditLogResponse,
)
from app.schemas.common import PaginatedResponse

router = APIRouter()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session_reference(session_id: uuid.UUID) -> str:
    return hashlib.sha256(f"vulnscanner-admin:{session_id}".encode()).hexdigest()[:24]


def _active_sessions(db: Session, user_id: uuid.UUID) -> list[OperatorSession]:
    return list(db.scalars(
        select(OperatorSession).where(
            OperatorSession.user_id == user_id,
            OperatorSession.revoked_at.is_(None),
            OperatorSession.expires_at > _now(),
        ).order_by(OperatorSession.last_activity_at.desc())
    ).all())


def _session_summary(item: OperatorSession) -> AdminSessionSummary:
    return AdminSessionSummary(
        reference=_session_reference(item.id),
        login_time=item.created_at,
        last_activity=item.last_activity_at,
        expires_at=item.expires_at,
    )


def _user_summary(db: Session, user: User) -> AdminUserSummary:
    sessions = _active_sessions(db, user.id)
    last_activity = db.scalar(
        select(func.max(OperatorSession.last_activity_at)).where(OperatorSession.user_id == user.id)
    )
    total_scans = db.scalar(select(func.count(Scan.id)).where(Scan.owner_user_id == user.id)) or 0
    total_findings = db.scalar(
        select(func.count(Vulnerability.id)).join(Scan).where(Scan.owner_user_id == user.id)
    ) or 0
    total_reports = db.scalar(select(func.count(Report.id)).where(Report.owner_user_id == user.id)) or 0
    return AdminUserSummary(
        id=user.id,
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        password_change_required=user.password_change_required,
        version=user.version,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
        last_activity_at=last_activity,
        online=bool(sessions),
        active_sessions=len(sessions),
        total_scans=total_scans,
        total_findings=total_findings,
        total_reports=total_reports,
    )


def _user_detail(db: Session, user: User) -> AdminUserDetail:
    summary = _user_summary(db, user)
    event_rows = db.execute(
        select(AuditLog, User.username).outerjoin(User, AuditLog.actor_user_id == User.id).where(
            or_(
                AuditLog.actor_user_id == user.id,
                (AuditLog.resource_type == "user") & (AuditLog.resource_id == str(user.id)),
            )
        ).order_by(AuditLog.created_at.desc()).limit(20)
    ).all()
    return AdminUserDetail(
        **summary.model_dump(),
        sessions=[_session_summary(s) for s in _active_sessions(db, user.id)],
        recent_events=[_audit_response(row[0], row[1]) for row in event_rows],
    )


def _get_user(db: Session, user_id: uuid.UUID, *, lock: bool = False) -> User:
    statement = select(User).where(User.id == user_id)
    if lock:
        statement = statement.with_for_update()
    user = db.scalar(statement)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _protect_last_admin(db: Session, user: User, *, next_role: str, next_active: bool) -> None:
    if not (user.role == "admin" and user.is_active) or (next_role == "admin" and next_active):
        return
    admin_ids = list(db.scalars(
        select(User.id).where(User.role == "admin", User.is_active.is_(True)).with_for_update()
    ).all())
    if len(admin_ids) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The last active administrator cannot be disabled or demoted.",
        )


def _audit_response(item: AuditLog, actor_username: str | None = None) -> AuditLogResponse:
    return AuditLogResponse(
        id=item.id,
        created_at=item.created_at,
        actor_user_id=item.actor_user_id,
        actor_username=actor_username,
        event_type=item.event_type,
        outcome=item.outcome,
        resource_type=item.resource_type,
        resource_id=item.resource_id,
        ip_address=item.ip_address,
        metadata=item.metadata_json or {},
    )


def _scan_summary(db: Session, scan: Scan, owner_username: str | None = None) -> AdminScanSummary:
    duration = None
    if scan.started_at and scan.completed_at:
        duration = max(0, round((scan.completed_at - scan.started_at).total_seconds()))
    findings = db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan.id)) or 0
    return AdminScanSummary(
        id=scan.id,
        owner_user_id=scan.owner_user_id,
        owner_username=owner_username,
        target=scan.target,
        operation=scan.operation,
        authorization_mode=scan.authorization_mode,
        scan_type=scan.scan_type,
        status=scan.status,
        progress=scan.progress,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=duration,
        findings_count=findings,
        error_message=scan.error_message,
    )


def _discovery_summary(db: Session, scan: Scan, owner_username: str | None = None) -> AdminDiscoverySummary:
    hosts = db.scalar(
        select(func.count(func.distinct(ScanResult.host_address))).where(
            ScanResult.scan_id == scan.id,
            ScanResult.host_state == "up",
        )
    ) or 0
    return AdminDiscoverySummary(
        id=scan.id,
        owner_user_id=scan.owner_user_id,
        owner_username=owner_username,
        target=scan.target,
        target_kind=scan.target_kind,
        authorization_mode=scan.authorization_mode,
        status=scan.status,
        hosts_discovered=hosts,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
    )


@router.get("/overview", response_model=AdminOverview)
def overview(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminOverview:
    total_users = db.scalar(select(func.count(User.id))) or 0
    active_users = db.scalar(select(func.count(User.id)).where(User.is_active.is_(True))) or 0
    active_session_users = db.scalar(select(func.count(func.distinct(OperatorSession.user_id))).where(
        OperatorSession.user_id.is_not(None),
        OperatorSession.revoked_at.is_(None),
        OperatorSession.expires_at > _now(),
    )) or 0
    status_counts = dict(db.execute(select(Scan.status, func.count(Scan.id)).where(Scan.operation == "scan").group_by(Scan.status)).all())
    severity_counts = dict(db.execute(select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity)).all())
    recent_since = _now() - timedelta(days=days)
    recent_discovery_rows = db.execute(
        select(Scan, User.username).outerjoin(User, Scan.owner_user_id == User.id).where(
            Scan.operation == "discovery", Scan.created_at >= recent_since,
        ).order_by(Scan.created_at.desc()).limit(5)
    ).all()
    recent_audit_rows = db.execute(
        select(AuditLog, User.username).outerjoin(User, AuditLog.actor_user_id == User.id)
        .where(AuditLog.created_at >= recent_since).order_by(AuditLog.created_at.desc()).limit(10)
    ).all()
    total_scans = sum(status_counts.values())
    total_findings = sum(severity_counts.values())
    return AdminOverview(
        total_users=total_users,
        active_users=active_users,
        disabled_users=total_users - active_users,
        online_users=active_session_users,
        total_scans=total_scans,
        running_scans=status_counts.get("running", 0) + status_counts.get("queued", 0),
        completed_scans=status_counts.get("completed", 0),
        failed_scans=status_counts.get("failed", 0),
        cancelled_scans=status_counts.get("cancelled", 0),
        total_findings=total_findings,
        findings_by_severity={key: severity_counts.get(key, 0) for key in ("critical", "high", "medium", "low", "info")},
        recent_discoveries=[_discovery_summary(db, row[0], row[1]) for row in recent_discovery_rows],
        recent_activity=[_audit_response(row[0], row[1]) for row in recent_audit_rows],
        health=AdminHealth(
            backend="healthy",
            database="healthy",
            nmap="healthy" if scanner_service.nmap_available else "unavailable",
        ),
    )


@router.get("/users", response_model=PaginatedResponse[AdminUserSummary])
def list_users(
    search: str | None = None,
    role: str | None = Query(None, pattern="^(user|admin)$"),
    account_status: str | None = Query(None, pattern="^(active|disabled)$"),
    online: bool | None = None,
    sort: str = Query("created_at", pattern="^(created_at|updated_at|username|email|last_login_at)$"),
    direction: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AdminUserSummary]:
    query = select(User)
    if search and search.strip():
        term = f"%{search.strip()}%"
        predicates = [User.full_name.ilike(term), User.username.ilike(term), User.email.ilike(term)]
        try:
            predicates.append(User.id == uuid.UUID(search.strip()))
        except ValueError:
            pass
        query = query.where(or_(*predicates))
    if role:
        query = query.where(User.role == role)
    if account_status:
        query = query.where(User.is_active.is_(account_status == "active"))
    active_exists = select(OperatorSession.id).where(
        OperatorSession.user_id == User.id,
        OperatorSession.revoked_at.is_(None),
        OperatorSession.expires_at > _now(),
    ).exists()
    if online is not None:
        query = query.where(active_exists if online else ~active_exists)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    sort_column = getattr(User, sort)
    order = sort_column.asc() if direction == "asc" else sort_column.desc()
    users = db.scalars(query.order_by(order, User.id).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create([_user_summary(db, user) for user in users], total, page, size)


@router.get("/users/{user_id}", response_model=AdminUserDetail)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminUserDetail:
    return _user_detail(db, _get_user(db, user_id))


@router.patch("/users/{user_id}", response_model=AdminUserDetail)
def update_user(
    user_id: uuid.UUID,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminUserDetail:
    user = _get_user(db, user_id, lock=True)
    if user.version != payload.version:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This account changed since it was loaded. Refresh and retry.")
    changes = payload.model_dump(exclude={"version"}, exclude_none=True)
    if not changes:
        return _user_detail(db, user)
    next_role = str(changes.get("role", user.role))
    next_active = bool(changes.get("is_active", user.is_active))
    _protect_last_admin(db, user, next_role=next_role, next_active=next_active)
    before = {key: getattr(user, key) for key in changes}
    for key, value in changes.items():
        setattr(user, key, value)
    user.version += 1
    if ("role" in changes and before["role"] != user.role) or ("is_active" in changes and before["is_active"] != user.is_active):
        revoke_user_sessions(db, user.id)
    add_audit_event(
        db,
        "admin.user_updated",
        actor_user_id=operator.user_id,
        resource_type="user",
        resource_id=user.id,
        metadata={"before": before, "after": {key: getattr(user, key) for key in changes}},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email is already in use.") from exc
    db.refresh(user)
    return _user_detail(db, user)


def _set_account_active(db: Session, operator: AuthenticatedOperator, user_id: uuid.UUID, active: bool) -> AdminUserDetail:
    user = _get_user(db, user_id, lock=True)
    _protect_last_admin(db, user, next_role=user.role, next_active=active)
    user.is_active = active
    user.version += 1
    if not active:
        revoke_user_sessions(db, user.id)
    add_audit_event(
        db,
        "admin.user_enabled" if active else "admin.user_disabled",
        actor_user_id=operator.user_id,
        resource_type="user",
        resource_id=user.id,
    )
    db.commit()
    db.refresh(user)
    return _user_detail(db, user)


@router.post("/users/{user_id}/enable", response_model=AdminUserDetail)
def enable_user(user_id: uuid.UUID, db: Session = Depends(get_db), operator: AuthenticatedOperator = Depends(require_admin)) -> AdminUserDetail:
    return _set_account_active(db, operator, user_id, True)


@router.post("/users/{user_id}/disable", response_model=AdminUserDetail)
def disable_user(user_id: uuid.UUID, db: Session = Depends(get_db), operator: AuthenticatedOperator = Depends(require_admin)) -> AdminUserDetail:
    return _set_account_active(db, operator, user_id, False)


@router.post("/users/{user_id}/reset-password", response_model=AdminActionResponse)
def reset_password(
    user_id: uuid.UUID,
    payload: AdminPasswordResetRequest,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminActionResponse:
    user = _get_user(db, user_id, lock=True)
    user.password_hash = hash_password(payload.temporary_password)
    user.password_change_required = True
    user.version += 1
    revoke_user_sessions(db, user.id)
    add_audit_event(
        db,
        "admin.password_reset",
        actor_user_id=operator.user_id,
        resource_type="user",
        resource_id=user.id,
        metadata={"force_change_on_next_login": True},
    )
    db.commit()
    return AdminActionResponse(message="Temporary password set. Existing sessions were revoked and a password change is required at next login.")


@router.post("/users/{user_id}/revoke-sessions", response_model=AdminActionResponse)
def revoke_sessions(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminActionResponse:
    _get_user(db, user_id)
    count = revoke_user_sessions(db, user_id)
    add_audit_event(db, "admin.sessions_revoked", actor_user_id=operator.user_id, resource_type="user", resource_id=user_id, metadata={"count": count})
    db.commit()
    return AdminActionResponse(message=f"Revoked {count} active session(s).")


@router.post("/users/{user_id}/sessions/{reference}/revoke", response_model=AdminActionResponse)
def revoke_session(
    user_id: uuid.UUID,
    reference: str,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_admin),
) -> AdminActionResponse:
    target = next((item for item in _active_sessions(db, user_id) if hmac.compare_digest(_session_reference(item.id), reference)), None)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active session not found")
    target.revoked_at = _now()
    add_audit_event(db, "admin.session_revoked", actor_user_id=operator.user_id, resource_type="user", resource_id=user_id)
    db.commit()
    return AdminActionResponse(message="Session revoked.")


@router.get("/users/{user_id}/scans", response_model=PaginatedResponse[AdminScanSummary])
def user_scans(user_id: uuid.UUID, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _operator: AuthenticatedOperator = Depends(require_admin)) -> PaginatedResponse[AdminScanSummary]:
    user = _get_user(db, user_id)
    query = select(Scan).where(Scan.owner_user_id == user_id, Scan.operation == "scan")
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    scans = db.scalars(query.order_by(Scan.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create([_scan_summary(db, scan, user.username) for scan in scans], total, page, size)


@router.get("/users/{user_id}/reports", response_model=PaginatedResponse[AdminReportSummary])
def user_reports(user_id: uuid.UUID, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _operator: AuthenticatedOperator = Depends(require_admin)) -> PaginatedResponse[AdminReportSummary]:
    user = _get_user(db, user_id)
    query = select(Report).where(Report.owner_user_id == user_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    reports = db.scalars(query.order_by(Report.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    items = [AdminReportSummary(id=r.id, owner_user_id=r.owner_user_id, owner_username=user.username, scan_id=r.scan_id, report_code=r.report_code, name=r.name, target=r.target, report_type=r.report_type, format=r.format, status=r.status, total_findings=r.total_findings, created_at=r.created_at) for r in reports]
    return PaginatedResponse.create(items, total, page, size)


@router.get("/scans", response_model=PaginatedResponse[AdminScanSummary])
def list_scans(
    user_id: uuid.UUID | None = None,
    scan_status: str | None = Query(None, alias="status"),
    target: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AdminScanSummary]:
    query = select(Scan, User.username).outerjoin(User, Scan.owner_user_id == User.id).where(Scan.operation == "scan")
    if user_id:
        query = query.where(Scan.owner_user_id == user_id)
    if scan_status:
        query = query.where(Scan.status == scan_status)
    if target:
        query = query.where(Scan.target.ilike(f"%{target.strip()}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(Scan.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create([_scan_summary(db, row[0], row[1]) for row in rows], total, page, size)


@router.post("/scans/{scan_id}/cancel", response_model=AdminActionResponse)
def cancel_scan(scan_id: uuid.UUID, db: Session = Depends(get_db), operator: AuthenticatedOperator = Depends(require_admin)) -> AdminActionResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel scan with status '{scan.status}'")
    scanner_service.cancel(scan_id)
    if scanner_service.get_job(scan_id) is None:
        scan.status = "cancelled"
        scan.error_message = "Cancelled by administrator."
        scan.completed_at = _now()
    add_audit_event(db, "admin.scan_cancelled", actor_user_id=operator.user_id, resource_type="scan", resource_id=scan.id, metadata={"owner_user_id": str(scan.owner_user_id) if scan.owner_user_id else None})
    db.commit()
    return AdminActionResponse(message="Scan cancellation requested.")


@router.post("/scans/{scan_id}/report-access", response_model=AdminActionResponse)
def record_scan_report_access(scan_id: uuid.UUID, db: Session = Depends(get_db), operator: AuthenticatedOperator = Depends(require_admin)) -> AdminActionResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    add_audit_event(db, "admin.scan_report_downloaded", actor_user_id=operator.user_id, resource_type="scan", resource_id=scan.id, metadata={"owner_user_id": str(scan.owner_user_id) if scan.owner_user_id else None})
    db.commit()
    return AdminActionResponse(message="Report access recorded.")


@router.get("/reports", response_model=PaginatedResponse[AdminReportSummary])
def list_reports(
    user_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    search: str | None = None,
    report_status: str | None = Query(None, alias="status"),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AdminReportSummary]:
    query = select(Report, User.username).outerjoin(User, Report.owner_user_id == User.id)
    if user_id:
        query = query.where(Report.owner_user_id == user_id)
    if scan_id:
        query = query.where(Report.scan_id == scan_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Report.name.ilike(term), Report.target.ilike(term), Report.report_code.ilike(term)))
    if report_status:
        query = query.where(Report.status == report_status)
    if date_from:
        query = query.where(Report.created_at >= date_from)
    if date_to:
        query = query.where(Report.created_at <= date_to)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(Report.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    items = [AdminReportSummary(id=r.id, owner_user_id=r.owner_user_id, owner_username=username, scan_id=r.scan_id, report_code=r.report_code, name=r.name, target=r.target, report_type=r.report_type, format=r.format, status=r.status, total_findings=r.total_findings, created_at=r.created_at) for r, username in rows]
    return PaginatedResponse.create(items, total, page, size)


@router.post("/reports/{report_id}/download-event", response_model=AdminActionResponse)
def record_report_download(report_id: uuid.UUID, db: Session = Depends(get_db), operator: AuthenticatedOperator = Depends(require_admin)) -> AdminActionResponse:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    add_audit_event(db, "admin.report_downloaded", actor_user_id=operator.user_id, resource_type="report", resource_id=report.id, metadata={"owner_user_id": str(report.owner_user_id) if report.owner_user_id else None})
    db.commit()
    return AdminActionResponse(message="Report download recorded.")


@router.get("/vulnerabilities", response_model=PaginatedResponse[AdminVulnerabilitySummary])
def list_vulnerabilities(
    user_id: uuid.UUID | None = None,
    severity: str | None = None,
    finding_status: str | None = Query(None, alias="status"),
    target: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AdminVulnerabilitySummary]:
    query = select(Vulnerability, Scan, User.username).join(Scan, Vulnerability.scan_id == Scan.id).outerjoin(User, Scan.owner_user_id == User.id)
    if user_id:
        query = query.where(Scan.owner_user_id == user_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if finding_status:
        query = query.where(Vulnerability.status == finding_status)
    if target:
        query = query.where(Scan.target.ilike(f"%{target.strip()}%"))
    if date_from:
        query = query.where(Vulnerability.created_at >= date_from)
    if date_to:
        query = query.where(Vulnerability.created_at <= date_to)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(Vulnerability.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    items = [AdminVulnerabilitySummary(id=v.id, title=v.title, cve_id=v.cve_id, severity=v.severity, cvss_score=v.cvss_score, target=scan.target, port=v.port, scan_id=scan.id, owner_user_id=scan.owner_user_id, owner_username=username, status=v.status, created_at=v.created_at, remediation=v.remediation) for v, scan, username in rows]
    return PaginatedResponse.create(items, total, page, size)


@router.get("/discoveries", response_model=PaginatedResponse[AdminDiscoverySummary])
def list_discoveries(
    user_id: uuid.UUID | None = None,
    discovery_status: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AdminDiscoverySummary]:
    query = select(Scan, User.username).outerjoin(User, Scan.owner_user_id == User.id).where(Scan.operation == "discovery")
    if user_id:
        query = query.where(Scan.owner_user_id == user_id)
    if discovery_status:
        query = query.where(Scan.status == discovery_status)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(Scan.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create([_discovery_summary(db, row[0], row[1]) for row in rows], total, page, size)


@router.get("/audit-logs", response_model=PaginatedResponse[AuditLogResponse])
def list_audit_logs(
    event_type: str | None = None,
    outcome: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    _operator: AuthenticatedOperator = Depends(require_admin),
) -> PaginatedResponse[AuditLogResponse]:
    query = select(AuditLog, User.username).outerjoin(User, AuditLog.actor_user_id == User.id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if outcome:
        query = query.where(AuditLog.outcome == outcome)
    if actor_user_id:
        query = query.where(AuditLog.actor_user_id == actor_user_id)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if date_from:
        query = query.where(AuditLog.created_at >= date_from)
    if date_to:
        query = query.where(AuditLog.created_at <= date_to)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.execute(query.order_by(AuditLog.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return PaginatedResponse.create([_audit_response(row[0], row[1]) for row in rows], total, page, size)
