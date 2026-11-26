"""
VulnScanner — Phase 7: Asset Management & Drawer Backend Tests.

Validates:
- Auto-discovery ingestion into assets table on scan result persistence.
- Duplicate asset prevention across repeated scans of the same host target.
- Automatic scan.asset_id association when target matches an existing asset.
- Querying scan results by host without requiring scan_id.
- Validation that either scan_id or host must be specified for scan results.
- Filtering scans by asset_id.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import app
from app.models.asset import Asset
from app.models.authorized_target import AuthorizedTarget
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.scanner.nmap_service import scanner_service
from app.scanner.xml_parser import HostInfo, NmapScanSummary, PortInfo


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


class TestAssetDiscoveryIngestion:
    """Test auto-ingestion of discovered hosts and duplicate prevention."""

    def test_persist_results_auto_ingests_new_asset(self, db_session: Session):
        """When a scan discovers an unknown host, an Asset record is automatically ingested."""
        scan_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        scan = Scan(
            id=scan_id,
            target="192.168.1.50",
            scan_type="quick",
            status="running",
            progress=50,
            created_at=now,
        )
        db_session.add(scan)
        db_session.commit()

        # Mock Nmap summary discovering 192.168.1.50 with port 80 open
        summary = NmapScanSummary(
            nmap_version="7.94",
            args="nmap -sV -T3 -F -oX - 192.168.1.50",
            exit_status="success",
            hosts=[
                HostInfo(
                    address="192.168.1.50",
                    state="up",
                    hostname="gateway.internal",
                    ports=[
                        PortInfo(
                            portid=80,
                            protocol="tcp",
                            state="open",
                            service_name="http",
                            service_product="nginx",
                            service_version="1.24.0",
                        )
                    ],
                )
            ],
        )

        asyncio.run(scanner_service._persist_results(db_session, scan_id, summary))

        # Check Asset created
        asset = db_session.scalar(select(Asset).where(Asset.target == "192.168.1.50"))
        assert asset is not None
        assert asset.name == "gateway.internal"
        assert asset.target == "192.168.1.50"
        assert asset.asset_type == "server"

        # Check Scan is linked to this asset
        db_session.refresh(scan)
        assert scan.asset_id == asset.id
        assert scan.status == "completed"

    def test_persist_results_prevents_duplicate_assets_on_repeated_scans(self, db_session: Session):
        """Repeated scans of the same host target MUST NOT create duplicate assets."""
        now = datetime.now(timezone.utc)
        # Pre-existing manually registered or previously discovered asset
        existing_asset = Asset(
            id=uuid.uuid4(),
            name="Primary Gateway",
            target="10.0.0.1",
            asset_type="network",
            description="Core router",
            created_at=now,
            updated_at=now,
        )
        db_session.add(existing_asset)

        # Scan 1
        scan1_id = uuid.uuid4()
        scan1 = Scan(
            id=scan1_id,
            target="10.0.0.1",
            scan_type="quick",
            status="running",
            progress=50,
            created_at=now,
        )
        db_session.add(scan1)
        db_session.commit()

        summary1 = NmapScanSummary(
            nmap_version="7.94",
            args="nmap -sV 10.0.0.1",
            exit_status="success",
            hosts=[
                HostInfo(
                    address="10.0.0.1",
                    state="up",
                    hostname="router.lan",
                    ports=[PortInfo(portid=22, protocol="tcp", state="open", service_name="ssh")],
                )
            ],
        )

        asyncio.run(scanner_service._persist_results(db_session, scan1_id, summary1))

        # Scan 2 on the same host
        scan2_id = uuid.uuid4()
        scan2 = Scan(
            id=scan2_id,
            target="10.0.0.1",
            scan_type="network",
            status="running",
            progress=50,
            created_at=now,
        )
        db_session.add(scan2)
        db_session.commit()

        summary2 = NmapScanSummary(
            nmap_version="7.94",
            args="nmap -sn 10.0.0.1",
            exit_status="success",
            hosts=[
                HostInfo(
                    address="10.0.0.1",
                    state="up",
                    hostname="router.lan",
                    ports=[],
                )
            ],
        )

        asyncio.run(scanner_service._persist_results(db_session, scan2_id, summary2))

        # Check total assets with target 10.0.0.1
        assets = db_session.scalars(select(Asset).where(Asset.target == "10.0.0.1")).all()
        assert len(assets) == 1, "Duplicate assets were created for the same host target!"
        assert assets[0].id == existing_asset.id
        assert assets[0].name == "Primary Gateway", "Pre-existing custom asset name should not be overwritten"

        # Both scans must be linked to the same asset
        db_session.refresh(scan1)
        db_session.refresh(scan2)
        assert scan1.asset_id == existing_asset.id
        assert scan2.asset_id == existing_asset.id


class TestScanAndResultsAPI:
    """Test API endpoints for scan results and scans filtering."""

    def test_list_scan_results_by_host(self, client: TestClient, db_session: Session):
        """Scan results can be retrieved by host without providing scan_id."""
        now = datetime.now(timezone.utc)
        scan = Scan(
            id=uuid.uuid4(),
            target="192.168.1.100",
            scan_type="quick",
            status="completed",
            progress=100,
            created_at=now,
        )
        db_session.add(scan)
        result1 = ScanResult(
            id=uuid.uuid4(),
            scan_id=scan.id,
            host_address="192.168.1.100",
            host_state="up",
            port=443,
            protocol="tcp",
            port_state="open",
            service_name="https",
            created_at=now,
        )
        db_session.add(result1)
        db_session.commit()

        # Query by host
        res = client.get("/api/v1/scan-results?host=192.168.1.100")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["port"] == 443
        assert data["items"][0]["service_name"] == "https"

    def test_list_scan_results_without_scan_id_or_host_returns_400(self, client: TestClient):
        """Unconstrained scan result queries return 400 Bad Request."""
        res = client.get("/api/v1/scan-results")
        assert res.status_code == 400
        assert "Either 'scan_id' or 'host' must be specified" in res.json()["detail"]

    def test_list_scans_filter_by_asset_id(self, client: TestClient, db_session: Session):
        """Scans can be filtered by asset_id to show asset scan history."""
        now = datetime.now(timezone.utc)
        asset_a = Asset(id=uuid.uuid4(), name="Asset A", target="10.1.1.1", asset_type="server", created_at=now, updated_at=now)
        asset_b = Asset(id=uuid.uuid4(), name="Asset B", target="10.1.1.2", asset_type="server", created_at=now, updated_at=now)
        db_session.add_all([asset_a, asset_b])

        scan_a = Scan(id=uuid.uuid4(), asset_id=asset_a.id, target="10.1.1.1", scan_type="quick", status="completed", progress=100, created_at=now)
        scan_b = Scan(id=uuid.uuid4(), asset_id=asset_b.id, target="10.1.1.2", scan_type="quick", status="completed", progress=100, created_at=now)
        db_session.add_all([scan_a, scan_b])
        db_session.commit()

        res = client.get(f"/api/v1/scans?asset_id={asset_a.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(scan_a.id)

    def test_create_scan_auto_associates_existing_asset(self, client: TestClient, db_session: Session):
        """When creating a scan without asset_id, it auto-associates with an existing matching asset."""
        now = datetime.now(timezone.utc)
        # Authorize target
        auth_target = AuthorizedTarget(
            id=uuid.uuid4(),
            target="127.0.0.1",
            description="Localhost",
            is_enabled=True,
            created_at=now,
        )
        db_session.add(auth_target)

        # Create Asset
        asset = Asset(
            id=uuid.uuid4(),
            name="Local Test Asset",
            target="127.0.0.1",
            asset_type="server",
            created_at=now,
            updated_at=now,
        )
        db_session.add(asset)
        db_session.commit()

        # Create scan without providing asset_id
        res = client.post(
            "/api/v1/scans",
            json={"target": "127.0.0.1", "scan_type": "quick"},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["asset_id"] == str(asset.id), "Scan should automatically link to matching asset ID"
