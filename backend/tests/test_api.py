"""
VulnScanner API — Phase 3 REST API tests.

Covers:
- Asset CRUD, search, pagination, safe deletion
- Scan lifecycle, creation in queued status, cancellation, state transitions
- Vulnerability listing, filtering, search, and retrieval
- Dashboard metrics aggregation and empty-database behavior

Uses an isolated in-memory SQLite database to guarantee zero modification
of the development PostgreSQL database.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import create_app
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Create a completely isolated in-memory database for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = session_factory()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """TestClient wired with isolated test database."""
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ── Asset API Tests ──────────────────────────────────────────────────────────


class TestAssetAPI:
    """Tests for /api/v1/assets"""

    def test_list_assets_empty(self, client: TestClient) -> None:
        response = client.get("/api/v1/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["page"] == 1
        assert data["pages"] == 1

    def test_create_asset_success(self, client: TestClient) -> None:
        payload = {
            "name": "Production Web Server",
            "asset_type": "server",
            "target": "192.168.1.100",
            "description": "Primary nginx reverse proxy",
        }
        response = client.post("/api/v1/assets", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == payload["name"]
        assert data["asset_type"] == "server"
        assert data["target"] == payload["target"]
        assert data["description"] == payload["description"]
        assert "id" in data
        assert "created_at" in data

    def test_create_asset_invalid_input(self, client: TestClient) -> None:
        # Missing required fields
        response = client.post("/api/v1/assets", json={"name": ""})
        assert response.status_code == 422

        # Invalid asset type
        response = client.post(
            "/api/v1/assets",
            json={"name": "Test", "asset_type": "invalid_type", "target": "10.0.0.1"},
        )
        assert response.status_code == 422

    def test_get_asset_by_id(self, client: TestClient) -> None:
        create_resp = client.post(
            "/api/v1/assets",
            json={"name": "API Gateway", "asset_type": "api", "target": "api.domain.com"},
        )
        asset_id = create_resp.json()["id"]

        get_resp = client.get(f"/api/v1/assets/{asset_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == asset_id
        assert get_resp.json()["name"] == "API Gateway"

    def test_get_asset_not_found(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        response = client.get(f"/api/v1/assets/{random_id}")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_update_asset(self, client: TestClient) -> None:
        create_resp = client.post(
            "/api/v1/assets",
            json={"name": "Old Name", "asset_type": "workstation", "target": "10.0.0.50"},
        )
        asset_id = create_resp.json()["id"]

        patch_resp = client.patch(
            f"/api/v1/assets/{asset_id}",
            json={"name": "New Name", "description": "Updated workstation"},
        )
        assert patch_resp.status_code == 200
        updated = patch_resp.json()
        assert updated["name"] == "New Name"
        assert updated["description"] == "Updated workstation"
        assert updated["asset_type"] == "workstation"

    def test_update_asset_not_found(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        response = client.patch(f"/api/v1/assets/{random_id}", json={"name": "X"})
        assert response.status_code == 404

    def test_delete_asset(self, client: TestClient) -> None:
        create_resp = client.post(
            "/api/v1/assets",
            json={"name": "To Delete", "asset_type": "network", "target": "10.0.0.254"},
        )
        asset_id = create_resp.json()["id"]

        del_resp = client.delete(f"/api/v1/assets/{asset_id}")
        assert del_resp.status_code == 204

        # Confirm deleted
        get_resp = client.get(f"/api/v1/assets/{asset_id}")
        assert get_resp.status_code == 404

    def test_delete_asset_not_found(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        response = client.delete(f"/api/v1/assets/{random_id}")
        assert response.status_code == 404

    def test_asset_search_and_pagination(self, client: TestClient) -> None:
        # Create 3 assets
        client.post("/api/v1/assets", json={"name": "Alpha Server", "asset_type": "server", "target": "10.0.1.1"})
        client.post("/api/v1/assets", json={"name": "Beta Database", "asset_type": "server", "target": "10.0.1.2"})
        client.post("/api/v1/assets", json={"name": "Gamma Gateway", "asset_type": "network", "target": "10.0.2.1"})

        # Search by name
        res = client.get("/api/v1/assets?search=Alpha")
        assert res.status_code == 200
        assert res.json()["total"] == 1
        assert res.json()["items"][0]["name"] == "Alpha Server"

        # Search by target IP
        res = client.get("/api/v1/assets?search=10.0.2")
        assert res.status_code == 200
        assert res.json()["total"] == 1
        assert res.json()["items"][0]["name"] == "Gamma Gateway"

        # Filter by type
        res = client.get("/api/v1/assets?asset_type=server")
        assert res.status_code == 200
        assert res.json()["total"] == 2

        # Pagination
        res = client.get("/api/v1/assets?page=1&size=2")
        assert len(res.json()["items"]) == 2
        assert res.json()["total"] == 3
        assert res.json()["pages"] == 2


# ── Scan API Tests ───────────────────────────────────────────────────────────


class TestScanAPI:
    """Tests for /api/v1/scans"""

    @pytest.fixture(autouse=True)
    def setup_scan_api(self, db_session: Session):
        from app.models.authorized_target import AuthorizedTarget
        from unittest.mock import patch, MagicMock

        targets = ["example.com", "10.0.0.10", "1.1.1.1", "target.org"]
        for t in targets:
            db_session.add(
                AuthorizedTarget(
                    id=uuid.uuid4(),
                    target=t,
                    is_enabled=True,
                    description="Test target",
                    created_at=datetime.now(timezone.utc),
                )
            )
        db_session.commit()

        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            yield

    def test_list_scans_empty(self, client: TestClient) -> None:
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_create_scan_queued_status(self, client: TestClient) -> None:
        payload = {"target": "example.com", "scan_type": "full"}
        response = client.post("/api/v1/scans", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["target"] == "example.com"
        assert data["scan_type"] == "full"
        assert data["status"] == "queued"
        assert data["progress"] == 0
        assert data["asset_id"] is None
        assert "id" in data

    def test_create_scan_with_valid_asset(self, client: TestClient) -> None:
        # Create asset first
        asset_resp = client.post(
            "/api/v1/assets",
            json={"name": "Target Host", "asset_type": "server", "target": "10.0.0.10"},
        )
        asset_id = asset_resp.json()["id"]

        # Create scan linked to asset
        scan_resp = client.post(
            "/api/v1/scans",
            json={"asset_id": asset_id, "target": "10.0.0.10", "scan_type": "network"},
        )
        assert scan_resp.status_code == 201
        assert scan_resp.json()["asset_id"] == asset_id

    def test_create_scan_with_invalid_asset(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        scan_resp = client.post(
            "/api/v1/scans",
            json={"asset_id": random_id, "target": "10.0.0.10", "scan_type": "quick"},
        )
        assert scan_resp.status_code == 404
        assert "asset" in scan_resp.json()["detail"].lower()

    def test_get_scan_by_id(self, client: TestClient) -> None:
        create_resp = client.post("/api/v1/scans", json={"target": "1.1.1.1", "scan_type": "quick"})
        scan_id = create_resp.json()["id"]

        get_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == scan_id

    def test_get_scan_not_found(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        response = client.get(f"/api/v1/scans/{random_id}")
        assert response.status_code == 404

    def test_cancel_queued_scan(self, client: TestClient) -> None:
        create_resp = client.post("/api/v1/scans", json={"target": "target.org", "scan_type": "web"})
        scan_id = create_resp.json()["id"]

        cancel_resp = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert cancel_resp.status_code == 200
        data = cancel_resp.json()
        assert data["status"] == "cancelled"
        assert data["completed_at"] is not None

    def test_cancel_already_cancelled_scan_is_idempotent(self, client: TestClient) -> None:
        create_resp = client.post("/api/v1/scans", json={"target": "target.org", "scan_type": "web"})
        scan_id = create_resp.json()["id"]

        client.post(f"/api/v1/scans/{scan_id}/cancel")
        # Cancel again
        second_cancel = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert second_cancel.status_code == 200
        assert second_cancel.json()["status"] == "cancelled"

    def test_cancel_completed_scan_fails(self, client: TestClient, db_session: Session) -> None:
        create_resp = client.post("/api/v1/scans", json={"target": "target.org", "scan_type": "web"})
        scan_id = uuid.UUID(create_resp.json()["id"])

        # Manually simulate a completed scan in DB
        scan = db_session.get(Scan, scan_id)
        assert scan is not None
        scan.status = "completed"
        scan.progress = 100
        db_session.commit()

        cancel_resp = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert cancel_resp.status_code == 400
        assert "cannot cancel" in cancel_resp.json()["detail"].lower()


# ── Vulnerability API Tests ──────────────────────────────────────────────────


class TestVulnerabilityAPI:
    """Tests for /api/v1/vulnerabilities"""

    def test_list_vulnerabilities_empty(self, client: TestClient) -> None:
        response = client.get("/api/v1/vulnerabilities")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_list_and_filter_vulnerabilities(self, client: TestClient, db_session: Session) -> None:
        # Create scan to associate vulnerabilities
        scan = Scan(
            id=uuid.uuid4(),
            target="10.0.0.1",
            scan_type="full",
            status="completed",
            progress=100,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(scan)
        db_session.commit()

        # Add 2 vulnerabilities
        v1 = Vulnerability(
            id=uuid.uuid4(),
            scan_id=scan.id,
            title="SQL Injection in auth route",
            cve_id="CVE-2023-1234",
            severity="critical",
            cvss_score=9.8,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        v2 = Vulnerability(
            id=uuid.uuid4(),
            scan_id=scan.id,
            title="TLS 1.0 Supported",
            severity="low",
            cvss_score=3.7,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add_all([v1, v2])
        db_session.commit()

        # All vulns
        res = client.get("/api/v1/vulnerabilities")
        assert res.status_code == 200
        assert res.json()["total"] == 2

        # Filter by severity
        res_crit = client.get("/api/v1/vulnerabilities?severity=critical")
        assert res_crit.json()["total"] == 1
        assert res_crit.json()["items"][0]["title"] == "SQL Injection in auth route"

        # Search by CVE
        res_cve = client.get("/api/v1/vulnerabilities?cve_id=2023-1234")
        assert res_cve.json()["total"] == 1

        # Search by keyword
        res_search = client.get("/api/v1/vulnerabilities?search=TLS")
        assert res_search.json()["total"] == 1
        assert res_search.json()["items"][0]["severity"] == "low"

    def test_get_vulnerability_by_id(self, client: TestClient, db_session: Session) -> None:
        scan = Scan(id=uuid.uuid4(), target="1.2.3.4", scan_type="web", status="queued", progress=0, created_at=datetime.now(timezone.utc))
        db_session.add(scan)
        db_session.commit()

        vuln_id = uuid.uuid4()
        vuln = Vulnerability(
            id=vuln_id,
            scan_id=scan.id,
            title="Cross-Site Scripting (XSS)",
            severity="high",
            cvss_score=7.5,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()

        res = client.get(f"/api/v1/vulnerabilities/{vuln_id}")
        assert res.status_code == 200
        assert res.json()["title"] == "Cross-Site Scripting (XSS)"
        assert res.json()["cvss_score"] == 7.5

    def test_get_vulnerability_not_found(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        res = client.get(f"/api/v1/vulnerabilities/{random_id}")
        assert res.status_code == 404


# ── Dashboard API Tests ──────────────────────────────────────────────────────


class TestDashboardAPI:
    """Tests for /api/v1/dashboard"""

    def test_dashboard_empty_database(self, client: TestClient) -> None:
        response = client.get("/api/v1/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 0
        assert data["total_scans"] == 0
        assert data["active_scans"] == 0
        assert data["completed_scans"] == 0
        assert data["failed_scans"] == 0
        assert data["cancelled_scans"] == 0
        assert data["discovered_hosts"] == 0
        assert data["total_vulnerabilities"] == 0
        assert data["severity_counts"] == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert data["recent_scans"] == []
        assert data["recent_vulnerabilities"] == []

    def test_dashboard_aggregates(self, client: TestClient, db_session: Session) -> None:
        # Create an asset
        asset = Asset(
            id=uuid.uuid4(),
            name="Web App",
            asset_type="web",
            target="app.test",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(asset)

        # Create 1 queued, 1 running, 1 completed scan
        s1 = Scan(id=uuid.uuid4(), asset_id=asset.id, target="app.test", scan_type="quick", status="queued", progress=0, created_at=datetime.now(timezone.utc))
        s2 = Scan(id=uuid.uuid4(), asset_id=asset.id, target="app.test", scan_type="full", status="running", progress=50, created_at=datetime.now(timezone.utc))
        s3 = Scan(id=uuid.uuid4(), asset_id=asset.id, target="app.test", scan_type="full", status="completed", progress=100, created_at=datetime.now(timezone.utc))
        db_session.add_all([s1, s2, s3])

        # Create vulnerabilities
        v1 = Vulnerability(id=uuid.uuid4(), scan_id=s3.id, title="Crit 1", severity="critical", cvss_score=9.0, status="open", created_at=datetime.now(timezone.utc))
        v2 = Vulnerability(id=uuid.uuid4(), scan_id=s3.id, title="High 1", severity="high", cvss_score=7.0, status="open", created_at=datetime.now(timezone.utc))
        v3 = Vulnerability(id=uuid.uuid4(), scan_id=s3.id, title="Med 1", severity="medium", cvss_score=5.0, status="open", created_at=datetime.now(timezone.utc))
        db_session.add_all([v1, v2, v3])
        db_session.commit()

        response = client.get("/api/v1/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 1
        assert data["total_scans"] == 3
        assert data["active_scans"] == 2  # queued + running
        assert data["completed_scans"] == 1
        assert data["failed_scans"] == 0
        assert data["cancelled_scans"] == 0
        assert data["discovered_hosts"] == 0
        assert data["total_vulnerabilities"] == 3
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 1
        assert data["severity_counts"]["medium"] == 1
        assert data["severity_counts"]["low"] == 0
        assert len(data["recent_scans"]) == 3
        assert len(data["recent_vulnerabilities"]) == 3
