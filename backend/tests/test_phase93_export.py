"""
VulnScanner API — Phase 9.3: Report Export Backend Tests.

Covers:
- Exporting a saved report as PDF (Content-Type: application/pdf, genuine %PDF-1.4 header).
- Exporting a saved report as CSV (Content-Type: text/csv, formula injection protections).
- Exporting a saved report as JSON (Content-Type: application/json, structured payload).
- Meaningful Content-Disposition attachment filenames with report name and scan date.
- 404 response for non-existent report IDs during export.
- 422 validation response for unsupported export format values.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import app
from app.models.report import Report


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session: Session):
    """FastAPI test client with database dependency override."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_report(db_session: Session) -> Report:
    """Create a persistent sample report in DB."""
    report = Report(
        id=uuid.uuid4(),
        report_code="RPT-20261028-TEST01",
        name="Quarterly Perimeter Audit",
        target="192.168.10.0/24",
        report_type="executive",
        format="pdf",
        status="ready",
        file_size="1.2 MB",
        scan_date="2026-10-28",
        date_from="2026-10-01",
        date_to="2026-10-28",
        critical_count=1,
        high_count=2,
        medium_count=3,
        low_count=4,
        info_count=5,
        total_findings=15,
        security_score=82,
        total_assets=10,
        total_scans=4,
        snapshot_data={"test": "data"},
    )
    db_session.add(report)
    db_session.commit()
    db_session.refresh(report)
    return report


def test_export_saved_report_as_pdf(client: TestClient, sample_report: Report):
    """GET /reports/{id}/export?format=pdf returns genuine binary PDF."""
    resp = client.get(f"/api/v1/reports/{sample_report.id}/export?format=pdf")
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert "attachment;" in resp.headers["content-disposition"]
    assert "Quarterly_Perimeter_Audit" in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].endswith('.pdf"')

    # Verify genuine binary PDF signature
    content = resp.content
    assert content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in content
    assert b"Quarterly Perimeter Audit" in content


def test_export_saved_report_as_csv(client: TestClient, sample_report: Report):
    """GET /reports/{id}/export?format=csv returns CSV with formula sanitization."""
    resp = client.get(f"/api/v1/reports/{sample_report.id}/export?format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment;" in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].endswith('.csv"')

    text = resp.text
    assert "# VulnScanner Security Report Export" in text
    assert "Quarterly Perimeter Audit" in text
    assert "Critical Findings,1" in text
    assert "Total Findings,15" in text


def test_export_saved_report_as_json(client: TestClient, sample_report: Report):
    """GET /reports/{id}/export?format=json returns structured report json."""
    resp = client.get(f"/api/v1/reports/{sample_report.id}/export?format=json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert "attachment;" in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].endswith('.json"')

    data = resp.json()
    assert data["name"] == "Quarterly Perimeter Audit"
    assert data["report_code"] == "RPT-20261028-TEST01"
    assert data["findings_summary"]["critical"] == 1
    assert data["findings_summary"]["total"] == 15


def test_export_report_by_report_code(client: TestClient, sample_report: Report):
    """Exporting works via human-friendly report_code as well as UUID."""
    resp = client.get(f"/api/v1/reports/{sample_report.report_code}/export?format=pdf")
    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF-1.4")


def test_export_nonexistent_report_returns_404(client: TestClient):
    """Exporting a non-existent report returns 404."""
    fake_id = uuid.uuid4()
    resp = client.get(f"/api/v1/reports/{fake_id}/export?format=pdf")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_export_invalid_format_returns_422(client: TestClient, sample_report: Report):
    """Unsupported export format returns 422 Unprocessable Entity."""
    resp = client.get(f"/api/v1/reports/{sample_report.id}/export?format=exe")
    assert resp.status_code == 422


def test_export_csv_formula_injection_protection(client: TestClient, db_session: Session):
    """Malicious formula triggers in report name or target are neutralized in backend CSV export."""
    malicious_report = Report(
        id=uuid.uuid4(),
        report_code="RPT-MALICIOUS",
        name="=cmd|' /C calc'!A0",
        target="+192.168.1.1, @badserver",
        report_type="executive",
        format="csv",
        status="ready",
        file_size="84 KB",
        scan_date="2026-10-28",
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        total_findings=0,
    )
    db_session.add(malicious_report)
    db_session.commit()

    resp = client.get(f"/api/v1/reports/{malicious_report.id}/export?format=csv")
    assert resp.status_code == 200
    text = resp.text
    # Must start with apostrophe to neutralize spreadsheet formula
    assert "'=cmd|' /C calc'!A0" in text or "''=cmd" in text
    assert "'+192.168.1.1" in text or "'+" in text
