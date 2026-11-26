"""Regression tests for scan-specific report composition."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import AuthenticatedOperator, require_authentication
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.vulnerability import Vulnerability


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session: Session):
    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_scan_report_uses_selected_scan_and_persisted_records(client: TestClient, db_session: Session):
    started = datetime.now(timezone.utc) - timedelta(seconds=74)
    scan = Scan(
        target="192.0.2.24",
        scan_type="quick",
        status="completed",
        progress=100,
        created_at=started - timedelta(seconds=2),
        started_at=started,
        completed_at=started + timedelta(seconds=74),
    )
    other_scan = Scan(target="198.51.100.8", scan_type="full", status="completed", progress=100)
    db_session.add_all([scan, other_scan])
    db_session.flush()
    db_session.add_all([
        ScanResult(
            scan_id=scan.id,
            host_address="192.0.2.24",
            hostname="lab.example",
            host_state="up",
            port=22,
            protocol="tcp",
            port_state="open",
            service_name="ssh",
            service_product="OpenSSH",
            service_version="9.6",
            service_extra_info="protocol 2.0",
        ),
        ScanResult(
            scan_id=scan.id,
            host_address="192.0.2.24",
            host_state="up",
            port=443,
            protocol="tcp",
            port_state="filtered",
        ),
        ScanResult(
            scan_id=other_scan.id,
            host_address="198.51.100.8",
            host_state="up",
            port=80,
            protocol="tcp",
            port_state="open",
            service_name="http",
        ),
        Vulnerability(
            scan_id=scan.id,
            title="Recorded SSH weakness",
            cve_id="CVE-2026-0001",
            severity="high",
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L",
            description="Confirmed by the recorded test fixture.",
            evidence="Safe fixture evidence.",
            remediation="Upgrade the affected service.",
            port=22,
            status="confirmed",
        ),
    ])
    db_session.commit()

    response = client.get(f"/api/v1/reports/scans/{scan.id}")

    assert response.status_code == 200
    report = response.json()
    assert report["scan_id"] == str(scan.id)
    assert report["target"] == "192.0.2.24"
    assert report["duration_seconds"] == 74
    assert report["summary"] == {
        "total_ports_examined": None,
        "recorded_port_entries": 2,
        "open_ports": 1,
        "closed_or_filtered_ports": 1,
        "identified_services": 1,
        "findings": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
    }
    assert [(item["port"], item["protocol"], item["service_name"]) for item in report["ports"]] == [
        (22, "tcp", "ssh"),
        (443, "tcp", None),
    ]
    assert report["findings"][0]["service_name"] == "ssh"
    assert report["findings"][0]["title"] == "Recorded SSH weakness"
    assert "198.51.100.8" not in str(report)
    assert report["authorization_mode"] is None
    assert report["recorded_configuration"] is None


@pytest.mark.parametrize("scan_status", ["queued", "running", "completed", "failed", "cancelled"])
def test_scan_report_preserves_incomplete_and_empty_states(
    client: TestClient, db_session: Session, scan_status: str,
):
    scan = Scan(
        target="localhost",
        scan_type="quick",
        status=scan_status,
        progress=50 if scan_status == "running" else 0,
        error_message="Safe scanner message" if scan_status == "failed" else None,
    )
    db_session.add(scan)
    db_session.commit()

    response = client.get(f"/api/v1/reports/scans/{scan.id}")

    assert response.status_code == 200
    report = response.json()
    assert report["status"] == scan_status
    assert report["port_inventory_recorded"] is False
    assert report["ports"] == []
    assert report["summary"]["total_ports_examined"] is None


def test_scan_report_missing_scan_returns_404(client: TestClient):
    response = client.get(f"/api/v1/reports/scans/{uuid.uuid4()}")
    assert response.status_code == 404


def test_scan_report_requires_authentication(db_session: Session):
    def override_db():
        yield db_session

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as unauthenticated_client:
            response = unauthenticated_client.get(f"/api/v1/reports/scans/{uuid.uuid4()}")
        assert response.status_code == 401
    finally:
        app.dependency_overrides.clear()
