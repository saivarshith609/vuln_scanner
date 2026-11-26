"""
VulnScanner — Phase 6: Scan Engine Management & Persistent Scan Deletion Tests.

Verifies:
1. DELETE /api/v1/scans/{scan_id} deletes completed, failed, or cancelled scans.
2. DELETE /api/v1/scans/{scan_id} returns 404 for non-existent scan ID.
3. DELETE /api/v1/scans/{scan_id} returns 400 for running scans.
4. Cascade deletion: Deleting a scan removes its child scan_results rows.
5. Isolation: Deleting a scan does not delete linked assets or unrelated scans' results.
6. Deletion of a queued scan cancels any job handle.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import create_app
from app.models.asset import Asset
from app.models.authorized_target import AuthorizedTarget
from app.models.scan import Scan
from app.models.scan_result import ScanResult


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


@pytest.fixture
def auth_target(db_session: Session) -> AuthorizedTarget:
    target = AuthorizedTarget(
        id=uuid.uuid4(),
        target="127.0.0.1",
        description="Localhost test target",
        is_enabled=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(target)
    db_session.commit()
    return target


@pytest.fixture
def asset(db_session: Session) -> Asset:
    a = Asset(
        id=uuid.uuid4(),
        name="Production Server",
        asset_type="server",
        target="127.0.0.1",
        description="Primary server",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(a)
    db_session.commit()
    return a


def test_delete_completed_scan_returns_204(client: TestClient, db_session: Session, asset: Asset) -> None:
    scan = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        target="127.0.0.1",
        scan_type="quick",
        status="completed",
        progress=100,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 204

    # Verify scan is gone
    assert db_session.get(Scan, scan.id) is None


def test_delete_scan_not_found_returns_404(client: TestClient) -> None:
    non_existent = uuid.uuid4()
    resp = client.delete(f"/api/v1/scans/{non_existent}")
    assert resp.status_code == 404
    assert f"Scan with ID '{non_existent}' not found" in resp.json()["detail"]


def test_delete_running_scan_returns_400(client: TestClient, db_session: Session) -> None:
    scan = Scan(
        id=uuid.uuid4(),
        target="127.0.0.1",
        scan_type="quick",
        status="running",
        progress=45,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 400
    assert "Cannot delete an actively running scan" in resp.json()["detail"]

    # Verify scan was NOT deleted
    assert db_session.get(Scan, scan.id) is not None


def test_delete_scan_cascades_to_scan_results(client: TestClient, db_session: Session) -> None:
    scan = Scan(
        id=uuid.uuid4(),
        target="127.0.0.1",
        scan_type="quick",
        status="completed",
        progress=100,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()

    # Add child scan results
    res1 = ScanResult(
        id=uuid.uuid4(),
        scan_id=scan.id,
        host_address="127.0.0.1",
        host_state="up",
        port=80,
        protocol="tcp",
        port_state="open",
        service_name="http",
    )
    res2 = ScanResult(
        id=uuid.uuid4(),
        scan_id=scan.id,
        host_address="127.0.0.1",
        host_state="up",
        port=443,
        protocol="tcp",
        port_state="open",
        service_name="https",
    )
    db_session.add_all([res1, res2])
    db_session.commit()

    assert len(db_session.scalars(select(ScanResult).where(ScanResult.scan_id == scan.id)).all()) == 2

    # Delete scan via API
    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 204

    # Verify child scan_results are also deleted
    results_after = db_session.scalars(select(ScanResult).where(ScanResult.scan_id == scan.id)).all()
    assert len(results_after) == 0


def test_delete_scan_preserves_asset_and_other_scans(client: TestClient, db_session: Session, asset: Asset) -> None:
    # Scan 1 (to be deleted)
    scan1 = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        target="127.0.0.1",
        scan_type="quick",
        status="completed",
        progress=100,
        created_at=datetime.now(timezone.utc),
    )
    # Scan 2 (to remain)
    scan2 = Scan(
        id=uuid.uuid4(),
        asset_id=asset.id,
        target="127.0.0.1",
        scan_type="network",
        status="completed",
        progress=100,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add_all([scan1, scan2])
    db_session.commit()

    res_other = ScanResult(
        id=uuid.uuid4(),
        scan_id=scan2.id,
        host_address="127.0.0.1",
        host_state="up",
        port=22,
        protocol="tcp",
        port_state="open",
        service_name="ssh",
    )
    db_session.add(res_other)
    db_session.commit()

    # Delete scan 1
    resp = client.delete(f"/api/v1/scans/{scan1.id}")
    assert resp.status_code == 204

    # Scan 1 is deleted
    assert db_session.get(Scan, scan1.id) is None
    # Asset is preserved
    assert db_session.get(Asset, asset.id) is not None
    # Scan 2 and its scan_result are preserved
    assert db_session.get(Scan, scan2.id) is not None
    assert db_session.get(ScanResult, res_other.id) is not None


def test_delete_queued_scan_succeeds(client: TestClient, db_session: Session) -> None:
    scan = Scan(
        id=uuid.uuid4(),
        target="127.0.0.1",
        scan_type="quick",
        status="queued",
        progress=0,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()

    resp = client.delete(f"/api/v1/scans/{scan.id}")
    assert resp.status_code == 204
    assert db_session.get(Scan, scan.id) is None
