"""
VulnScanner API — Security Report endpoints (Phase 9.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.core.audit import add_audit_event
from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.vulnerability import Vulnerability
from app.schemas.common import PaginatedResponse
from app.schemas.report import (
    FindingsSummary,
    ReportCreate,
    ReportDetailResponse,
    ReportResponse,
    ScanReportDetail,
    ScanReportFinding,
    ScanReportPort,
    ScanReportSummary,
)

router = APIRouter()


def _report_to_response(r: Report) -> ReportResponse:
    """Helper to convert ORM Report into ReportResponse schema."""
    summary = FindingsSummary(
        critical=r.critical_count,
        high=r.high_count,
        medium=r.medium_count,
        low=r.low_count,
        info=r.info_count,
        total=r.total_findings,
    )
    return ReportResponse(
        id=r.id,
        report_code=r.report_code or str(r.id),
        name=r.name,
        target=r.target,
        report_type=r.report_type,
        format=r.format,
        status=r.status,
        scan_date=r.scan_date,
        date_from=r.date_from,
        date_to=r.date_to,
        file_size=r.file_size,
        findings_summary=summary,
        security_score=r.security_score,
        total_assets=r.total_assets,
        total_scans=r.total_scans,
        created_at=r.created_at,
        updated_at=r.updated_at,
        download_url=f"/api/v1/reports/{r.id}/export",
    )


def _report_to_detail(r: Report) -> ReportDetailResponse:
    """Helper to convert ORM Report into ReportDetailResponse schema with snapshot."""
    base = _report_to_response(r)
    return ReportDetailResponse(
        **base.model_dump(),
        snapshot_data=r.snapshot_data,
    )


@router.get(
    "",
    response_model=PaginatedResponse[ReportResponse],
    summary="List saved reports",
    description="Retrieve a paginated list of saved reports with optional filters for type and search term.",
)
def list_reports(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    report_type: str | None = Query(None, alias="type", description="Filter by report type"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status (ready, generating, failed)"),
    search: str | None = Query(None, description="Search term for report name or target"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[ReportResponse]:
    query = select(Report)
    if not operator.is_admin:
        query = query.where(Report.owner_user_id == operator.user_id)

    if report_type and report_type.lower() != "all":
        query = query.where(Report.report_type == report_type.strip().lower())

    if status_filter and status_filter.lower() != "all":
        query = query.where(Report.status == status_filter.strip().lower())

    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Report.name.ilike(term), Report.target.ilike(term)))

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = db.scalar(count_query) or 0

    # Fetch page ordered by newest first
    offset = (page - 1) * size
    stmt = query.order_by(Report.created_at.desc()).offset(offset).limit(size)
    db_reports = db.scalars(stmt).all()

    items = [_report_to_response(r) for r in db_reports]
    return PaginatedResponse.create(items=items, total=total, page=page, size=size)


@router.post(
    "",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and persist a new report",
    description="Creates a saved security report with a live snapshot of vulnerabilities and assets.",
)
def create_report(
    payload: ReportCreate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ReportResponse:
    # Validate date range logic
    if payload.date_from and payload.date_to and payload.date_from > payload.date_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="date_from must be on or before date_to",
        )

    # Idempotency check: if an identical report was saved in the last 5 seconds, return it
    recent_threshold = datetime.now(timezone.utc) - timedelta(seconds=5)
    existing_query = select(Report).where(
            Report.name == payload.name.strip(),
            Report.target == payload.target.strip(),
            Report.created_at >= recent_threshold,
        )
    if not operator.is_admin:
        existing_query = existing_query.where(Report.owner_user_id == operator.user_id)
    existing = db.scalars(existing_query).first()
    if existing:
        return _report_to_response(existing)

    # Compute live vulnerability severity breakdown
    def severity_count(severity: str) -> int:
        query = select(func.count(Vulnerability.id)).join(Scan).where(Vulnerability.severity == severity)
        if not operator.is_admin:
            query = query.where(Scan.owner_user_id == operator.user_id)
        return db.scalar(query) or 0

    crit_count = severity_count("critical")
    high_count = severity_count("high")
    med_count = severity_count("medium")
    low_count = severity_count("low")
    info_count = severity_count("info")
    total_findings = crit_count + high_count + med_count + low_count + info_count

    # Compute security score (Phase 5 standardized formula)
    raw_deductions = crit_count * 25 + high_count * 15 + med_count * 5 + low_count * 1
    security_score = max(0, min(100, 100 - raw_deductions))

    # Total registered assets and scans
    asset_count_query = select(func.count(Asset.id))
    scan_count_query = select(func.count(Scan.id))
    if not operator.is_admin:
        asset_count_query = asset_count_query.where(Asset.owner_user_id == operator.user_id)
        scan_count_query = scan_count_query.where(Scan.owner_user_id == operator.user_id)
    total_assets = db.scalar(asset_count_query) or 0
    total_scans = db.scalar(scan_count_query) or 0

    # Build safe findings snapshot (up to 50 findings for reproducibility)
    findings_stmt = select(Vulnerability).join(Scan).order_by(Vulnerability.cvss_score.desc()).limit(50)
    if not operator.is_admin:
        findings_stmt = findings_stmt.where(Scan.owner_user_id == operator.user_id)
    top_findings = db.scalars(findings_stmt).all()
    findings_list: list[dict[str, Any]] = [
        {
            "id": str(v.id),
            "title": v.title,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            "status": v.status,
            "remediation": v.remediation,
        }
        for v in top_findings
    ]

    snapshot: dict[str, Any] = {
        "parameters": {
            "name": payload.name.strip(),
            "target": payload.target.strip(),
            "report_type": payload.report_type.lower(),
            "date_from": payload.date_from,
            "date_to": payload.date_to,
        },
        "metrics": {
            "total_assets": total_assets,
            "total_scans": total_scans,
            "security_score": security_score,
            "findings_summary": {
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "info": info_count,
                "total": total_findings,
            },
        },
        "findings": findings_list,
    }

    report_id = uuid.uuid4()
    code_suffix = str(report_id).split("-")[0].upper()
    now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_code = f"RPT-{now_date.replace('-', '')}-{code_suffix}"

    file_size = "84 KB" if payload.format.lower() == "csv" else "1.2 MB"

    report = Report(
        id=report_id,
        owner_user_id=operator.user_id,
        report_code=report_code,
        name=payload.name.strip(),
        target=payload.target.strip(),
        report_type=payload.report_type.lower(),
        format=payload.format.lower(),
        status="ready",
        file_size=file_size,
        scan_date=now_date,
        date_from=payload.date_from,
        date_to=payload.date_to,
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count,
        info_count=info_count,
        total_findings=total_findings,
        security_score=security_score,
        total_assets=total_assets,
        total_scans=total_scans,
        snapshot_data=snapshot,
    )

    db.add(report)
    add_audit_event(
        db, "report.created", actor_user_id=operator.user_id,
        resource_type="report", resource_id=report.id,
        metadata={"target": report.target, "report_type": report.report_type},
    )
    db.commit()
    db.refresh(report)

    return _report_to_response(report)


@router.get(
    "/scans/{scan_id}",
    response_model=ScanReportDetail,
    summary="Get a scan-specific security report",
    description="Returns the selected scan and its persisted discovery and vulnerability records.",
)
def get_scan_report(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ScanReportDetail:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found",
        )
    require_owner(operator, scan.owner_user_id)

    results = db.scalars(
        select(ScanResult)
        .where(ScanResult.scan_id == scan_id)
        .order_by(ScanResult.host_address, ScanResult.port, ScanResult.protocol)
    ).all()
    vulnerabilities = db.scalars(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.created_at, Vulnerability.id)
    ).all()

    port_results = [item for item in results if item.port is not None]
    open_ports = sum(1 for item in port_results if item.port_state == "open")
    closed_or_filtered = sum(
        1 for item in port_results if item.port_state in {"closed", "filtered", "closed|filtered", "open|filtered"}
    )
    identified_services = sum(
        1
        for item in port_results
        if item.service_name or item.service_product or item.service_version
    )
    severity_counts = {
        severity: sum(1 for finding in vulnerabilities if finding.severity == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    service_by_port = {
        item.port: item.service_name
        for item in port_results
        if item.port is not None and item.service_name
    }

    duration_seconds: int | None = None
    if scan.started_at and scan.completed_at:
        duration_seconds = max(0, round((scan.completed_at - scan.started_at).total_seconds()))

    return ScanReportDetail(
        scan_id=scan.id,
        target=scan.target,
        status=scan.status,
        progress=scan.progress,
        scan_profile=scan.scan_type,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=duration_seconds,
        error_message=scan.error_message,
        resolved_addresses=list(dict.fromkeys(item.host_address for item in results if item.host_address)),
        port_inventory_recorded=bool(port_results),
        summary=ScanReportSummary(
            total_ports_examined=None,
            recorded_port_entries=len(port_results),
            open_ports=open_ports,
            closed_or_filtered_ports=closed_or_filtered,
            identified_services=identified_services,
            findings=FindingsSummary(
                **severity_counts,
                total=len(vulnerabilities),
            ),
        ),
        ports=[
            ScanReportPort(
                id=item.id,
                host_address=item.host_address,
                hostname=item.hostname,
                host_state=item.host_state,
                port=item.port,
                protocol=item.protocol,
                state=item.port_state,
                service_name=item.service_name,
                product=item.service_product,
                version=item.service_version,
                extra_information=item.service_extra_info,
            )
            for item in port_results
        ],
        findings=[
            ScanReportFinding(
                id=item.id,
                title=item.title,
                severity=item.severity,
                cve_id=item.cve_id,
                cvss_score=item.cvss_score,
                cvss_vector=item.cvss_vector,
                affected_target=scan.target,
                port=item.port,
                service_name=service_by_port.get(item.port),
                description=item.description,
                evidence=item.evidence,
                remediation=item.remediation,
                status=item.status,
            )
            for item in vulnerabilities
        ],
        limitations=[
            "The report contains only discovery and vulnerability records persisted for this scan.",
            "The exact number of ports examined is unavailable because the executed Nmap configuration is not retained.",
            "A detected open port or service is an observation, not proof of a vulnerability.",
        ],
    )


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
    summary="Get saved report by ID",
    description="Retrieve a single saved report by its UUID or report code, including snapshot findings.",
)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> ReportDetailResponse:
    report: Report | None = None

    # Try UUID lookup first
    try:
        parsed_uuid = uuid.UUID(report_id)
        report = db.scalars(select(Report).where(Report.id == parsed_uuid)).first()
    except ValueError:
        pass

    # Fallback to report_code lookup
    if not report:
        report = db.scalars(select(Report).where(Report.report_code == report_id)).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' not found",
        )
    require_owner(operator, report.owner_user_id)

    if operator.is_admin:
        add_audit_event(
            db, "admin.report_viewed", actor_user_id=operator.user_id,
            resource_type="report", resource_id=report.id,
            metadata={"owner_user_id": str(report.owner_user_id) if report.owner_user_id else None},
        )
        db.commit()

    return _report_to_detail(report)


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete saved report",
    description="Deletes a saved security report from PostgreSQL.",
)
def delete_report(
    report_id: str,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> Response:
    report: Report | None = None
    try:
        parsed_uuid = uuid.UUID(report_id)
        report = db.scalars(select(Report).where(Report.id == parsed_uuid)).first()
    except ValueError:
        pass

    if not report:
        report = db.scalars(select(Report).where(Report.report_code == report_id)).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' not found",
        )
    require_owner(operator, report.owner_user_id)

    db.delete(report)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _sanitize_csv_cell(val: Any) -> str:
    """Sanitize CSV cell to prevent formula injection per OWASP standards."""
    if val is None:
        return ""
    s = str(val)
    if not s:
        return ""
    import re
    if re.match(r"^[\s\x00-\x1f]*[=+\-@\t\r]", s):
        s = f"'{s}"
    if "," in s or '"' in s or "\n" in s:
        return f'"{s.replace(chr(34), chr(34) + chr(34))}"'
    return s


def _generate_report_pdf_bytes(report: Report) -> bytes:
    """Generate genuine binary PDF/1.4 document for the report."""
    title = (report.name or "VulnScanner Security Report").replace("(", "[").replace(")", "]")
    code = report.report_code or str(report.id)
    target = (report.target or "All Assets").replace("(", "[").replace(")", "]")
    report_type = (report.report_type or "executive").upper()
    scan_date = report.scan_date or ""
    score = f"{report.security_score}/100" if report.security_score is not None else "N/A"
    total_findings = report.total_findings

    lines = [
        f"Document ID: {code}",
        f"Classification: CONFIDENTIAL // TLP:AMBER",
        f"Report Type: {report_type} REPORT",
        f"Target Scope: {target}",
        f"Scan Date: {scan_date}",
        f"Security Posture Score: {score}",
        f"Total Assets Evaluated: {report.total_assets}",
        f"Total Scans In Scope: {report.total_scans}",
        "---",
        f"Findings Summary (Total: {total_findings}):",
        f"  Critical: {report.critical_count} | High: {report.high_count} | Medium: {report.medium_count} | Low: {report.low_count} | Info: {report.info_count}",
    ]
    if total_findings == 0:
        lines.append("Clean Audit Status: Zero active vulnerability findings detected.")

    content_lines = ["BT", "/F1 16 Tf", "50 740 Td", f"({title}) Tj", "/F1 10 Tf"]
    y = 705
    for line in lines:
        sanitized_line = line.replace("\\", "\\\\").replace("(", "[").replace(")", "]")
        content_lines.extend(["1 0 0 1 50 " + str(y) + " Tm", f"({sanitized_line}) Tj"])
        y -= 16
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(content)} >>\nstream\n".encode("latin-1") + content + b"\nendstream\nendobj\n",
    ]

    pdf = b"%PDF-1.4\n"
    offsets = [len(pdf)]
    for obj in objects:
        offsets.append(offsets[-1] + len(obj))
        pdf += obj

    xref_offset = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    for offset in offsets[:-1]:
        pdf += f"{offset:010d} 00000 n \n".encode("ascii")
    pdf += f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    return pdf


@router.get(
    "/{report_id}/export",
    summary="Export saved report as file",
    description="Export a saved security report in PDF, CSV, or JSON format.",
)
def export_saved_report(
    report_id: str,
    export_format: str = Query("pdf", alias="format", pattern="^(pdf|csv|json|PDF|CSV|JSON)$"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> Response:
    report: Report | None = None
    try:
        parsed_uuid = uuid.UUID(report_id)
        report = db.scalars(select(Report).where(Report.id == parsed_uuid)).first()
    except ValueError:
        pass

    if not report:
        report = db.scalars(select(Report).where(Report.report_code == report_id)).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' not found",
        )
    require_owner(operator, report.owner_user_id)

    fmt = export_format.strip().lower()
    if operator.is_admin:
        add_audit_event(
            db, "admin.report_downloaded", actor_user_id=operator.user_id,
            resource_type="report", resource_id=report.id,
            metadata={
                "format": fmt,
                "owner_user_id": str(report.owner_user_id) if report.owner_user_id else None,
            },
        )
        db.commit()
    import re
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", report.name or "Security_Report")
    safe_date = re.sub(r"[^a-zA-Z0-9_\-]", "_", report.scan_date or "export")

    if fmt == "csv":
        s = _sanitize_csv_cell
        rows = [
            "# VulnScanner Security Report Export",
            f"# Report: {s(report.name)}",
            f"# Target: {s(report.target)}",
            f"# Type: {s(report.report_type)}",
            f"# Scan Date: {s(report.scan_date)}",
            f"# Status: {s(report.status)}",
            "",
            "Metric,Count",
            f"Critical Findings,{report.critical_count}",
            f"High Findings,{report.high_count}",
            f"Medium Findings,{report.medium_count}",
            f"Low Findings,{report.low_count}",
            f"Info Findings,{report.info_count}",
            f"Total Findings,{report.total_findings}",
        ]
        csv_bytes = "\n".join(rows).encode("utf-8")
        filename = f"{safe_name}_{safe_date}.csv"
        return Response(
            content=csv_bytes,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    elif fmt == "json":
        import json
        payload = _report_to_detail(report).model_dump(mode="json")
        json_bytes = json.dumps(payload, indent=2).encode("utf-8")
        filename = f"{safe_name}_{safe_date}.json"
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:  # pdf
        pdf_bytes = _generate_report_pdf_bytes(report)
        filename = f"{safe_name}_{safe_date}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
