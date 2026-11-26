"""
VulnScanner API — Phase 2 tests: Pydantic schemas, model definitions,
database health endpoint, and database dependency.

These tests run without a live PostgreSQL server.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import create_app
from app.schemas import (
    AssetCreate,
    AssetResponse,
    ScanCreate,
    ScanUpdate,
    VulnerabilityCreate,
    VulnerabilityUpdate,
)


def get_client() -> TestClient:
    """Create a fresh test client from the application factory."""
    return TestClient(create_app())


# ── Asset schema tests ──────────────────────────────────────────────────────


class TestAssetSchemas:
    """Validate AssetCreate / AssetResponse schemas."""

    def test_valid_asset_create(self) -> None:
        asset = AssetCreate(
            name="prod-api",
            asset_type="server",
            target="192.168.1.1",
        )
        assert asset.name == "prod-api"
        assert asset.asset_type.value == "server"

    def test_asset_create_missing_name_fails(self) -> None:
        with pytest.raises(ValidationError):
            AssetCreate(asset_type="server", target="10.0.0.1")  # type: ignore[call-arg]

    def test_asset_create_empty_name_fails(self) -> None:
        with pytest.raises(ValidationError):
            AssetCreate(name="", asset_type="server", target="10.0.0.1")

    def test_asset_create_invalid_type_fails(self) -> None:
        with pytest.raises(ValidationError):
            AssetCreate(name="x", asset_type="spaceship", target="10.0.0.1")

    def test_asset_response_from_attributes(self) -> None:
        """Ensure from_attributes mode works for ORM-like objects."""
        from datetime import datetime, timezone

        mock_obj = MagicMock()
        mock_obj.id = "550e8400-e29b-41d4-a716-446655440000"
        mock_obj.name = "web-01"
        mock_obj.asset_type = "web"
        mock_obj.target = "example.com"
        mock_obj.description = None
        mock_obj.created_at = datetime.now(timezone.utc)
        mock_obj.updated_at = datetime.now(timezone.utc)

        resp = AssetResponse.model_validate(mock_obj, from_attributes=True)
        assert resp.name == "web-01"


# ── Scan schema tests ───────────────────────────────────────────────────────


class TestScanSchemas:
    """Validate ScanCreate / ScanUpdate schemas."""

    def test_valid_scan_create(self) -> None:
        scan = ScanCreate(target="192.168.0.0/24", scan_type="network")
        assert scan.target == "192.168.0.0/24"

    def test_scan_create_invalid_type_fails(self) -> None:
        with pytest.raises(ValidationError):
            ScanCreate(target="x", scan_type="nuclear")

    def test_scan_progress_valid_range(self) -> None:
        update = ScanUpdate(progress=50)
        assert update.progress == 50

    def test_scan_progress_zero(self) -> None:
        update = ScanUpdate(progress=0)
        assert update.progress == 0

    def test_scan_progress_hundred(self) -> None:
        update = ScanUpdate(progress=100)
        assert update.progress == 100

    def test_scan_progress_negative_fails(self) -> None:
        with pytest.raises(ValidationError):
            ScanUpdate(progress=-1)

    def test_scan_progress_over_100_fails(self) -> None:
        with pytest.raises(ValidationError):
            ScanUpdate(progress=101)

    def test_scan_invalid_status_fails(self) -> None:
        with pytest.raises(ValidationError):
            ScanUpdate(status="exploded")


# ── Vulnerability schema tests ──────────────────────────────────────────────


class TestVulnerabilitySchemas:
    """Validate VulnerabilityCreate / VulnerabilityUpdate schemas."""

    def test_valid_vulnerability_create(self) -> None:
        vuln = VulnerabilityCreate(
            scan_id="550e8400-e29b-41d4-a716-446655440000",
            title="SQL Injection",
            severity="critical",
            cvss_score=9.8,
        )
        assert vuln.severity.value == "critical"
        assert vuln.cvss_score == 9.8

    def test_cvss_score_zero(self) -> None:
        vuln = VulnerabilityCreate(
            scan_id="550e8400-e29b-41d4-a716-446655440000",
            title="Info Finding",
            severity="info",
            cvss_score=0.0,
        )
        assert vuln.cvss_score == 0.0

    def test_cvss_score_max(self) -> None:
        vuln = VulnerabilityCreate(
            scan_id="550e8400-e29b-41d4-a716-446655440000",
            title="Critical Bug",
            severity="critical",
            cvss_score=10.0,
        )
        assert vuln.cvss_score == 10.0

    def test_cvss_score_negative_fails(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id="550e8400-e29b-41d4-a716-446655440000",
                title="Bad",
                severity="high",
                cvss_score=-0.1,
            )

    def test_cvss_score_over_10_fails(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id="550e8400-e29b-41d4-a716-446655440000",
                title="Bad",
                severity="high",
                cvss_score=10.1,
            )

    def test_invalid_severity_fails(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id="550e8400-e29b-41d4-a716-446655440000",
                title="Bad",
                severity="extreme",
            )

    def test_valid_port_range(self) -> None:
        vuln = VulnerabilityCreate(
            scan_id="550e8400-e29b-41d4-a716-446655440000",
            title="Open Port",
            severity="low",
            port=443,
        )
        assert vuln.port == 443

    def test_port_zero_fails(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id="550e8400-e29b-41d4-a716-446655440000",
                title="Bad",
                severity="low",
                port=0,
            )

    def test_port_over_65535_fails(self) -> None:
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                scan_id="550e8400-e29b-41d4-a716-446655440000",
                title="Bad",
                severity="low",
                port=70000,
            )

    def test_vulnerability_update_partial(self) -> None:
        update = VulnerabilityUpdate(status="resolved")
        assert update.status is not None
        assert update.title is None


# ── Model definition tests ──────────────────────────────────────────────────


class TestModelDefinitions:
    """Verify ORM model structure without requiring a live database."""

    def test_asset_model_has_expected_columns(self) -> None:
        from app.models.asset import Asset
        columns = {c.name for c in Asset.__table__.columns}
        assert columns >= {"id", "name", "asset_type", "target", "created_at", "updated_at"}

    def test_scan_model_has_expected_columns(self) -> None:
        from app.models.scan import Scan
        columns = {c.name for c in Scan.__table__.columns}
        assert columns >= {"id", "asset_id", "target", "scan_type", "status", "progress", "created_at"}

    def test_vulnerability_model_has_expected_columns(self) -> None:
        from app.models.vulnerability import Vulnerability
        columns = {c.name for c in Vulnerability.__table__.columns}
        assert columns >= {"id", "scan_id", "title", "severity", "cvss_score", "status", "created_at"}

    def test_scan_progress_check_constraint_exists(self) -> None:
        from app.models.scan import Scan
        constraints = {c.name for c in Scan.__table__.constraints if hasattr(c, "name") and c.name}
        assert "ck_scans_progress" in constraints

    def test_scan_status_check_constraint_exists(self) -> None:
        from app.models.scan import Scan
        constraints = {c.name for c in Scan.__table__.constraints if hasattr(c, "name") and c.name}
        assert "ck_scans_status" in constraints

    def test_vulnerability_severity_check_constraint_exists(self) -> None:
        from app.models.vulnerability import Vulnerability
        constraints = {c.name for c in Vulnerability.__table__.constraints if hasattr(c, "name") and c.name}
        assert "ck_vulns_severity" in constraints

    def test_vulnerability_cvss_check_constraint_exists(self) -> None:
        from app.models.vulnerability import Vulnerability
        constraints = {c.name for c in Vulnerability.__table__.constraints if hasattr(c, "name") and c.name}
        assert "ck_vulns_cvss" in constraints


# ── Database dependency tests ────────────────────────────────────────────────


class TestDatabaseDependency:
    """Test the get_db dependency behaviour (mocked)."""

    def test_get_db_yields_session(self) -> None:
        """get_db should yield a session and close it."""
        mock_session = MagicMock()
        mock_factory = MagicMock(return_value=mock_session)

        with patch("app.db.session.get_session_factory", return_value=mock_factory):
            from app.db.session import get_db
            gen = get_db()
            session = next(gen)
            assert session is mock_session
            # Exhaust the generator to trigger cleanup
            try:
                next(gen)
            except StopIteration:
                pass
            mock_session.close.assert_called_once()


# ── Database health endpoint tests ──────────────────────────────────────────


class TestDatabaseHealthEndpoint:
    """Tests for GET /api/v1/health/database (no live PostgreSQL required)."""

    def test_database_health_success(self) -> None:
        """When DB is reachable, return 200 with healthy status."""
        mock_db = MagicMock()
        app = create_app()
        app.dependency_overrides[__import__("app.db.session", fromlist=["get_db"]).get_db] = lambda: mock_db

        client = TestClient(app)
        response = client.get("/api/v1/health/database")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "reachable"

    def test_database_health_failure(self) -> None:
        """When DB is unreachable, return 503 without leaking details."""
        from app.db.session import get_db

        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("simulated failure")

        app = create_app()
        app.dependency_overrides[get_db] = lambda: mock_db

        client = TestClient(app)
        response = client.get("/api/v1/health/database")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "unreachable"
        # Ensure no credentials leak
        assert "password" not in str(data).lower()
        assert "changeme" not in str(data).lower()
