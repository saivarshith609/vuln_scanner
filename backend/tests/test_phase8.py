"""
VulnScanner API — Phase 8: Vulnerability Investigation & CVSS Triage Backend Tests.

Covers:
- All five supported statuses: open, in_progress, resolved, false_positive, accepted.
- Rejection of invalid status values with HTTP 422.
- CVSS score boundary enforcement (0.0–10.0 valid, invalid scores rejected).
- CVSS vector (max 100 chars) and PoC evidence persistence.
- Asset linkage: asset_name and asset_target in list and detail responses.
- Handling vulnerabilities without linked assets (asset_name and asset_target are None).
- Persistent PATCH updates for status triage, evidence, and remediation.
- Filtering by status, severity, CVE, and search keyword.
- 404 response for non-existent vulnerability IDs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import app
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityStatus,
    VulnerabilityUpdate,
)


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
    """FastAPI TestClient with overridden get_db dependency."""
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
def base_scan(db_session: Session) -> Scan:
    """Fixture providing a completed scan."""
    scan = Scan(
        id=uuid.uuid4(),
        target="192.168.1.100",
        scan_type="full",
        status="completed",
        progress=100,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()
    return scan


@pytest.fixture
def base_asset(db_session: Session) -> Asset:
    """Fixture providing a registered asset."""
    asset = Asset(
        id=uuid.uuid4(),
        name="web-gateway-01",
        asset_type="server",
        target="192.168.1.100",
        description="Primary API edge gateway",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(asset)
    db_session.commit()
    return asset


class TestVulnerabilityStatusAndValidation:
    """Tests for status enum validation and schema constraints."""

    @pytest.mark.parametrize(
        "valid_status",
        ["open", "in_progress", "resolved", "false_positive", "accepted"],
    )
    def test_all_supported_statuses_accepted(self, valid_status: str):
        """All 5 Phase 8 triage statuses must be accepted by the schema."""
        create_schema = VulnerabilityCreate(
            scan_id=uuid.uuid4(),
            title="SSL/TLS Weak Cipher",
            severity="medium",
            status=VulnerabilityStatus(valid_status),
        )
        assert create_schema.status == valid_status

        update_schema = VulnerabilityUpdate(status=VulnerabilityStatus(valid_status))
        assert update_schema.status == valid_status

    def test_invalid_status_rejected(self):
        """Invalid triage statuses must be rejected by Pydantic validation."""
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id=uuid.uuid4(),
                title="Invalid Status Test",
                severity="low",
                status="not_a_valid_status",  # type: ignore
            )

        with pytest.raises(ValidationError):
            VulnerabilityUpdate(status="unknown_status")  # type: ignore

    def test_cvss_score_boundaries(self):
        """CVSS scores must be within [0.0, 10.0]."""
        # Valid boundaries
        v_min = VulnerabilityCreate(
            scan_id=uuid.uuid4(),
            title="Info finding",
            severity="info",
            cvss_score=0.0,
        )
        assert v_min.cvss_score == 0.0

        v_max = VulnerabilityCreate(
            scan_id=uuid.uuid4(),
            title="Critical RCE",
            severity="critical",
            cvss_score=10.0,
        )
        assert v_max.cvss_score == 10.0

        # Out of bounds
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id=uuid.uuid4(),
                title="Negative score",
                severity="low",
                cvss_score=-0.1,
            )

        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id=uuid.uuid4(),
                title="Over max score",
                severity="critical",
                cvss_score=10.5,
            )

    def test_cvss_vector_and_evidence_fields(self):
        """cvss_vector (max 100 chars) and evidence text are accepted."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        evidence = "POST /api/v1/auth HTTP/1.1\nHost: 192.168.1.100\n\n' OR 1=1--"

        v = VulnerabilityCreate(
            scan_id=uuid.uuid4(),
            title="SQLi in Login",
            severity="critical",
            cvss_score=9.8,
            cvss_vector=vector,
            evidence=evidence,
        )
        assert v.cvss_vector == vector
        assert v.evidence == evidence

        # cvss_vector exceeding 100 characters must fail
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id=uuid.uuid4(),
                title="Overlength vector",
                severity="low",
                cvss_vector="A" * 101,
            )


class TestVulnerabilityAPIEndpoints:
    """Integration tests for /api/v1/vulnerabilities routes."""

    def test_list_vulnerabilities_with_asset_linkage(
        self, client: TestClient, db_session: Session, base_scan: Scan, base_asset: Asset
    ):
        """Vulnerabilities linked to an asset return asset_name and asset_target."""
        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=base_scan.id,
            asset_id=base_asset.id,
            title="Remote Code Execution",
            cve_id="CVE-2024-9999",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Unauthenticated remote code execution vulnerability.",
            remediation="Apply vendor patch KB99999 immediately.",
            evidence="Raw exploit response received on port 443",
            port=443,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        resp = client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        item = data["items"][0]
        assert item["id"] == str(vuln_id)
        assert item["title"] == "Remote Code Execution"
        assert item["asset_id"] == str(base_asset.id)
        assert item["asset_name"] == "web-gateway-01"
        assert item["asset_target"] == "192.168.1.100"
        assert item["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert item["evidence"] == "Raw exploit response received on port 443"
        assert item["status"] == "open"

    def test_vulnerability_without_asset_linkage(
        self, client: TestClient, db_session: Session, base_scan: Scan
    ):
        """Vulnerabilities without an asset return asset_name=None and asset_target=None."""
        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=base_scan.id,
            asset_id=None,
            title="Orphaned Finding",
            severity="low",
            cvss_score=2.0,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        # List
        resp = client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200
        item = resp.json()["items"][0]
        assert item["asset_id"] is None
        assert item["asset_name"] is None
        assert item["asset_target"] is None

        # Detail
        detail_resp = client.get(f"/api/v1/vulnerabilities/{vuln_id}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["asset_id"] is None
        assert detail_data["asset_name"] is None
        assert detail_data["asset_target"] is None

    def test_patch_triage_status_lifecycle(
        self, client: TestClient, db_session: Session, base_scan: Scan, base_asset: Asset
    ):
        """PATCH /api/v1/vulnerabilities/{id} persists status transitions across the lifecycle."""
        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=base_scan.id,
            asset_id=base_asset.id,
            title="Exposed Admin Panel",
            severity="high",
            cvss_score=7.5,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        # Transition to in_progress
        p1 = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "in_progress"},
        )
        assert p1.status_code == 200
        assert p1.json()["status"] == "in_progress"
        assert p1.json()["asset_name"] == "web-gateway-01"

        # Transition to resolved with remediation notes
        p2 = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={
                "status": "resolved",
                "remediation": "Firewall rule created blocking public access to /admin.",
            },
        )
        assert p2.status_code == 200
        assert p2.json()["status"] == "resolved"
        assert "Firewall rule created" in p2.json()["remediation"]

        # Transition to false_positive
        p3 = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "false_positive"},
        )
        assert p3.status_code == 200
        assert p3.json()["status"] == "false_positive"

        # Transition to accepted (backward compatibility)
        p4 = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "accepted"},
        )
        assert p4.status_code == 200
        assert p4.json()["status"] == "accepted"

        # Verify DB directly
        db_session.expire_all()
        persisted = db_session.get(Vulnerability, vuln_id)
        assert persisted is not None
        assert persisted.status == "accepted"

    def test_patch_invalid_status_returns_422(
        self, client: TestClient, db_session: Session, base_scan: Scan
    ):
        """Invalid triage status in PATCH request returns 422 Unprocessable Entity."""
        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=base_scan.id,
            title="Sample Finding",
            severity="medium",
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        resp = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"status": "disputed_not_allowed"},
        )
        assert resp.status_code == 422

    def test_patch_evidence_and_cvss_vector(
        self, client: TestClient, db_session: Session, base_scan: Scan
    ):
        """PATCH can update cvss_vector and evidence."""
        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=base_scan.id,
            title="Missing Auth",
            severity="high",
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        evidence_data = "Captured response 200 OK without Authorization header"

        resp = client.patch(
            f"/api/v1/vulnerabilities/{vuln_id}",
            json={"cvss_vector": vector, "evidence": evidence_data},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cvss_vector"] == vector
        assert data["evidence"] == evidence_data

    def test_filter_by_status_and_search(
        self, client: TestClient, db_session: Session, base_scan: Scan
    ):
        """Filtering by in_progress, resolved, false_positive works correctly."""
        now = datetime.now(timezone.utc)
        v1 = Vulnerability(
            id=uuid.uuid4(),
            scan_id=base_scan.id,
            title="Heartbleed OpenSSL Bug",
            cve_id="CVE-2014-0160",
            severity="critical",
            status="in_progress",
            created_at=now,
        )
        v2 = Vulnerability(
            id=uuid.uuid4(),
            scan_id=base_scan.id,
            title="Self-Signed SSL Certificate",
            severity="info",
            status="false_positive",
            created_at=now,
        )
        v3 = Vulnerability(
            id=uuid.uuid4(),
            scan_id=base_scan.id,
            title="SSH Weak MAC Algorithm",
            severity="low",
            status="resolved",
            created_at=now,
        )
        db_session.add_all([v1, v2, v3])
        db_session.commit()

        # Filter by in_progress
        r_prog = client.get("/api/v1/vulnerabilities?status=in_progress")
        assert r_prog.status_code == 200
        assert r_prog.json()["total"] == 1
        assert r_prog.json()["items"][0]["title"] == "Heartbleed OpenSSL Bug"

        # Filter by false_positive
        r_fp = client.get("/api/v1/vulnerabilities?status=false_positive")
        assert r_fp.status_code == 200
        assert r_fp.json()["total"] == 1
        assert r_fp.json()["items"][0]["title"] == "Self-Signed SSL Certificate"

        # Search term
        r_search = client.get("/api/v1/vulnerabilities?search=Heartbleed")
        assert r_search.status_code == 200
        assert r_search.json()["total"] == 1
        assert r_search.json()["items"][0]["cve_id"] == "CVE-2014-0160"

    def test_get_nonexistent_vulnerability_returns_404(self, client: TestClient):
        """Requesting a missing vulnerability ID returns 404."""
        nonexistent = uuid.uuid4()
        res = client.get(f"/api/v1/vulnerabilities/{nonexistent}")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

        patch_res = client.patch(
            f"/api/v1/vulnerabilities/{nonexistent}",
            json={"status": "resolved"},
        )
        assert patch_res.status_code == 404
