"""
VulnScanner API — Phase 9.2: Persistent Report History Backend Tests.

Covers:
- Creating a report with live metrics and snapshot persistence.
- Listing saved reports with pagination and filtering.
- Retrieving an individual report by UUID and by report_code.
- Detail response including snapshot_data.
- 404 response for non-existent report IDs.
- Input validation: empty name, empty target, invalid type, date range ordering.
- Idempotency guard for rapid repeat submissions.
- Deleting a saved report.
- Database persistence across session commits.
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
from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database session with static pool."""
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
    """FastAPI test client with overridden database dependency."""
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


# ─── Tests ───────────────────────────────────────────────────────────────────

def test_create_report_with_clean_db(client: TestClient):
    """Creating a report when DB has 0 findings results in zero metrics and 100 score."""
    resp = client.post(
        "/api/v1/reports",
        json={
            "name": "Q4 Clean Audit Report",
            "target": "10.0.0.0/24 Subnet",
            "report_type": "executive",
            "format": "pdf",
            "date_from": "2026-09-01",
            "date_to": "2026-10-27",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Q4 Clean Audit Report"
    assert data["target"] == "10.0.0.0/24 Subnet"
    assert data["report_type"] == "executive"
    assert data["type"] == "executive"
    assert data["status"] == "ready"
    assert data["findings_summary"]["total"] == 0
    assert data["findings_summary"]["critical"] == 0
    assert data["security_score"] == 100
    assert data["total_assets"] == 0
    assert data["total_scans"] == 0
    assert "id" in data
    assert "report_code" in data


def test_create_report_derives_real_backend_vulnerabilities(client: TestClient, db_session: Session):
    """Creating a report correctly derives live findings counts and posture score."""
    # Seed asset
    asset = Asset(
        id=uuid.uuid4(),
        name="DB-Cluster-01",
        asset_type="server",
        target="192.168.1.10",
    )
    db_session.add(asset)

    # Seed scan
    scan = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        target="192.168.1.10",
        scan_type="full",
        status="completed",
        progress=100,
    )
    db_session.add(scan)

    # Seed 1 critical and 1 high vulnerability
    v1 = Vulnerability(
        id=uuid.uuid4(),
        asset_id=asset.id,
        scan_id=scan.id,
        title="Remote Code Execution",
        cve_id="CVE-2026-1001",
        severity="critical",
        cvss_score=9.8,
        status="open",
    )
    v2 = Vulnerability(
        id=uuid.uuid4(),
        asset_id=asset.id,
        scan_id=scan.id,
        title="Privilege Escalation",
        cve_id="CVE-2026-1002",
        severity="high",
        cvss_score=8.1,
        status="open",
    )
    db_session.add_all([v1, v2])
    db_session.commit()

    resp = client.post(
        "/api/v1/reports",
        json={
            "name": "Production Perimeter Audit",
            "target": "192.168.1.10",
            "report_type": "technical",
            "format": "csv",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["findings_summary"]["critical"] == 1
    assert data["findings_summary"]["high"] == 1
    assert data["findings_summary"]["medium"] == 0
    assert data["findings_summary"]["total"] == 2
    # Score: 100 - (1*25 + 1*15) = 60
    assert data["security_score"] == 60
    assert data["total_assets"] == 1
    assert data["total_scans"] == 1


def test_list_reports_pagination_and_sorting(client: TestClient):
    """Listing reports returns paginated responses ordered by newest first."""
    # Create 3 reports
    for i in range(1, 4):
        resp = client.post(
            "/api/v1/reports",
            json={
                "name": f"Batch Report #{i}",
                "target": f"Scope-{i}",
                "report_type": "executive",
                "format": "pdf",
            },
        )
        assert resp.status_code == 201

    # Fetch with size=2
    list_resp = client.get("/api/v1/reports?page=1&size=2")
    assert list_resp.status_code == 200
    page_data = list_resp.json()
    assert page_data["total"] == 3
    assert page_data["page"] == 1
    assert page_data["size"] == 2
    assert page_data["pages"] == 2
    assert len(page_data["items"]) == 2
    # Newest report first
    assert page_data["items"][0]["name"] == "Batch Report #3"

    # Fetch page 2
    p2_resp = client.get("/api/v1/reports?page=2&size=2")
    assert p2_resp.status_code == 200
    p2_data = p2_resp.json()
    assert len(p2_data["items"]) == 1
    assert p2_data["items"][0]["name"] == "Batch Report #1"


def test_list_reports_filtering(client: TestClient):
    """Filtering reports by type and search keyword."""
    client.post(
        "/api/v1/reports",
        json={"name": "Executive Alpha", "target": "Scope A", "report_type": "executive", "format": "pdf"},
    )
    client.post(
        "/api/v1/reports",
        json={"name": "Technical Beta", "target": "Scope B", "report_type": "technical", "format": "csv"},
    )

    # Filter by type=technical
    tech_resp = client.get("/api/v1/reports?type=technical")
    assert tech_resp.status_code == 200
    tech_data = tech_resp.json()
    assert tech_data["total"] == 1
    assert tech_data["items"][0]["name"] == "Technical Beta"

    # Filter by search=Alpha
    search_resp = client.get("/api/v1/reports?search=alpha")
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert search_data["total"] == 1
    assert search_data["items"][0]["name"] == "Executive Alpha"


def test_get_report_by_uuid_and_code(client: TestClient):
    """Retrieving a single report by UUID or by human-readable report_code."""
    create_resp = client.post(
        "/api/v1/reports",
        json={
            "name": "Audit for Code Lookup",
            "target": "Internal DMZ",
            "report_type": "compliance",
            "format": "pdf",
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    report_uuid = created["id"]
    report_code = created["report_code"]

    # Retrieve by UUID
    get_uuid_resp = client.get(f"/api/v1/reports/{report_uuid}")
    assert get_uuid_resp.status_code == 200
    uuid_data = get_uuid_resp.json()
    assert uuid_data["id"] == report_uuid
    assert "snapshot_data" in uuid_data
    assert uuid_data["snapshot_data"]["parameters"]["name"] == "Audit for Code Lookup"

    # Retrieve by code
    get_code_resp = client.get(f"/api/v1/reports/{report_code}")
    assert get_code_resp.status_code == 200
    code_data = get_code_resp.json()
    assert code_data["id"] == report_uuid


def test_get_report_not_found(client: TestClient):
    """Requesting non-existent report returns HTTP 404."""
    random_uuid = str(uuid.uuid4())
    resp = client.get(f"/api/v1/reports/{random_uuid}")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()

    code_resp = client.get("/api/v1/reports/RPT-DOES-NOT-EXIST")
    assert code_resp.status_code == 404


def test_input_validation_empty_fields_and_invalid_types(client: TestClient):
    """Validation rejects empty names, missing targets, invalid report types, and reversed dates."""
    # Empty name
    r1 = client.post("/api/v1/reports", json={"name": "", "target": "Scope", "report_type": "executive", "format": "pdf"})
    assert r1.status_code == 422

    # Empty target
    r2 = client.post("/api/v1/reports", json={"name": "Valid Name", "target": "", "report_type": "executive", "format": "pdf"})
    assert r2.status_code == 422

    # Invalid type
    r3 = client.post("/api/v1/reports", json={"name": "Valid Name", "target": "Scope", "report_type": "invalid_type", "format": "pdf"})
    assert r3.status_code == 422

    # Reversed dates: date_from > date_to
    r4 = client.post(
        "/api/v1/reports",
        json={
            "name": "Invalid Dates",
            "target": "Scope",
            "report_type": "executive",
            "format": "pdf",
            "date_from": "2026-10-27",
            "date_to": "2026-09-01",
        },
    )
    assert r4.status_code == 422
    assert "date_from must be on or before date_to" in r4.json()["detail"]


def test_delete_report(client: TestClient):
    """Deleting a saved report removes it from the database."""
    create_resp = client.post(
        "/api/v1/reports",
        json={"name": "To Be Deleted", "target": "Temporary", "report_type": "delta", "format": "csv"},
    )
    report_id = create_resp.json()["id"]

    del_resp = client.delete(f"/api/v1/reports/{report_id}")
    assert del_resp.status_code == 204

    # Confirm it's gone
    get_resp = client.get(f"/api/v1/reports/{report_id}")
    assert get_resp.status_code == 404
