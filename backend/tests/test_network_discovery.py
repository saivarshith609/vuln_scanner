"""Network discovery, range authorization, inventory, and safety regressions."""

from __future__ import annotations

import asyncio
import textwrap
import uuid
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import AuthenticatedOperator, require_authentication
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.authorized_target import AuthorizedTarget
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.scanner.auth_service import (
    OnDemandAuthorizationRequiredError,
    TargetNotAuthorizedError,
    normalize_discovery_cidr,
    normalize_ip_range,
    validate_range_authorized,
)
from app.scanner.nmap_service import NmapScannerService
from app.scanner.service import NmapNotAvailableError
from app.scanner.xml_parser import parse_nmap_xml


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test", role="admin")
    with TestClient(app) as test_client:
        yield test_client


def authorize(db: Session, target: str) -> None:
    db.add(AuthorizedTarget(target=target, is_enabled=True))
    db.commit()


def test_cidr_normalization_and_size_bound() -> None:
    assert normalize_discovery_cidr("192.168.1.42/24", 4096) == ("192.168.1.0/24", 256)
    assert normalize_discovery_cidr("2001:db8::1/120", 4096) == ("2001:db8::/120", 256)
    with pytest.raises(ValueError, match="configured maximum"):
        normalize_discovery_cidr("10.0.0.0/8", 4096)


def test_ip_range_validation_and_safe_cidr_expansion() -> None:
    canonical, start, end, count, cidrs = normalize_ip_range("192.168.1.10", "192.168.1.20", 100)
    assert canonical == "192.168.1.10-192.168.1.20"
    assert (start, end, count) == ("192.168.1.10", "192.168.1.20", 11)
    assert cidrs == ["192.168.1.10/31", "192.168.1.12/30", "192.168.1.16/30", "192.168.1.20/32"]


@pytest.mark.parametrize(("start", "end", "message"), [
    ("192.168.1.20", "192.168.1.10", "must not exceed"),
    ("192.168.1.1", "2001:db8::1", "same IP family"),
    ("invalid", "192.168.1.2", "valid start and end"),
])
def test_invalid_ip_ranges(start: str, end: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_ip_range(start, end, 4096)


def test_oversized_range_is_rejected() -> None:
    with pytest.raises(ValueError, match="configured maximum"):
        normalize_ip_range("10.0.0.1", "10.0.20.1", 4096)


def test_range_requires_one_authorized_scope_containing_both_ends(db_session: Session) -> None:
    authorize(db_session, "192.168.10.0/24")
    validate_range_authorized("192.168.10.10", "192.168.10.50", db_session)
    with pytest.raises(TargetNotAuthorizedError):
        validate_range_authorized("192.168.10.250", "192.168.11.2", db_session)


def test_authorization_is_rechecked_immediately_before_discovery_launch(db_session: Session) -> None:
    scope = AuthorizedTarget(target="192.168.44.0/24", is_enabled=True)
    run = Scan(id=uuid.uuid4(), target="192.168.44.0/24", operation="discovery", target_kind="cidr", scan_type="network", status="queued", progress=0, authorization_mode="allow_list", authorization_confirmed=True)
    db_session.add_all([scope, run])
    db_session.commit()
    asyncio.run(NmapScannerService()._recheck_authorization(db_session, run.id))
    scope.is_enabled = False
    db_session.commit()
    with pytest.raises(TargetNotAuthorizedError):
        asyncio.run(NmapScannerService()._recheck_authorization(db_session, run.id))


def test_on_demand_discovery_recheck_requires_confirmation_and_bounded_scope(db_session: Session) -> None:
    run = Scan(
        id=uuid.uuid4(), target="192.168.44.0/24", operation="discovery",
        target_kind="cidr", scan_type="network", status="queued", progress=0,
        authorization_mode="on_demand", authorization_confirmed=True,
    )
    db_session.add(run)
    db_session.commit()
    asyncio.run(NmapScannerService()._recheck_authorization(db_session, run.id))

    run.authorization_confirmed = False
    db_session.commit()
    with pytest.raises(OnDemandAuthorizationRequiredError):
        asyncio.run(NmapScannerService()._recheck_authorization(db_session, run.id))

    run.authorization_confirmed = True
    run.target = "10.0.0.0/8"
    db_session.commit()
    with pytest.raises(ValueError, match="configured maximum"):
        asyncio.run(NmapScannerService()._recheck_authorization(db_session, run.id))


def test_discovery_xml_parses_hostname_mac_and_vendor() -> None:
    summary = parse_nmap_xml(textwrap.dedent("""\
        <nmaprun version="7.95"><host><status state="up"/>
        <address addr="192.168.1.8" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Devices"/>
        <hostnames><hostname name="printer.lab" type="PTR"/></hostnames>
        </host><runstats><finished exit="success"/></runstats></nmaprun>
    """))
    assert summary.hosts[0].hostname == "printer.lab"
    assert summary.hosts[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert summary.hosts[0].vendor == "Example Devices"


def test_create_cidr_discovery_uses_sn_and_normalized_target(client: TestClient, db_session: Session) -> None:
    authorize(db_session, "192.168.20.0/24")
    with (
        patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn", "-oX", "-", "192.168.20.0/24"]) as build,
        patch("app.api.routes.discoveries.scanner_service.launch") as launch,
    ):
        response = client.post("/api/v1/discoveries", json={
            "target_type": "cidr", "cidr": "192.168.20.55/24", "authorization_confirmed": True,
        })
    assert response.status_code == 201
    assert response.json()["target"] == "192.168.20.0/24"
    assert response.json()["target_kind"] == "cidr"
    build.assert_called_once_with("192.168.20.0/24", "network", target_args=["192.168.20.0/24"])
    assert launch.call_args.kwargs["target_args"] == ["192.168.20.0/24"]


def test_on_demand_cidr_discovery_succeeds_without_allow_list_and_is_auditable(db_session: Session) -> None:
    owner_id = uuid.uuid4()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(
        method="session", session_id=uuid.uuid4(), user_id=owner_id, role="user",
    )
    with (
        TestClient(app) as owned_client,
        patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn"]) as build,
        patch("app.api.routes.discoveries.scanner_service.launch") as launch,
    ):
        response = owned_client.post("/api/v1/discoveries", json={
            "target_type": "cidr",
            "cidr": "192.168.29.31/24",
            "authorization_mode": "on_demand",
            "authorization_confirmed": True,
        })

    assert response.status_code == 201
    body = response.json()
    assert body["target"] == "192.168.29.0/24"
    assert body["authorization_mode"] == "on_demand"
    assert body["authorization_confirmed"] is True
    assert body["authorization_confirmed_at"] is not None
    stored = db_session.get(Scan, uuid.UUID(body["id"]))
    assert stored is not None
    assert stored.owner_user_id == owner_id
    assert stored.scan_type == "network"
    assert stored.authorization_confirmed_at is not None
    assert stored.status == "queued"
    assert stored.error_message is None
    build.assert_called_once_with("192.168.29.0/24", "network", target_args=["192.168.29.0/24"])
    assert launch.call_args.args[2] == "network"
    assert launch.call_args.kwargs["target_args"] == ["192.168.29.0/24"]
    assert launch.call_args.kwargs["recheck_authorization"] is True


def test_on_demand_discovery_rejects_missing_confirmation_and_invalid_or_oversized_scope(client: TestClient) -> None:
    missing = client.post("/api/v1/discoveries", json={
        "target_type": "cidr", "cidr": "192.168.29.0/24",
        "authorization_mode": "on_demand", "authorization_confirmed": False,
    })
    assert missing.status_code == 403

    malformed = client.post("/api/v1/discoveries", json={
        "target_type": "cidr", "cidr": "192.168.29.0/99",
        "authorization_mode": "on_demand", "authorization_confirmed": True,
    })
    assert malformed.status_code == 422

    oversized = client.post("/api/v1/discoveries", json={
        "target_type": "cidr", "cidr": "10.0.0.0/8",
        "authorization_mode": "on_demand", "authorization_confirmed": True,
    })
    assert oversized.status_code == 422
    assert "configured maximum" in oversized.json()["detail"]


def test_create_range_discovery_passes_cidr_arguments_not_shell_text(client: TestClient, db_session: Session) -> None:
    authorize(db_session, "10.10.0.0/24")
    with (
        patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn"]) as build,
        patch("app.api.routes.discoveries.scanner_service.launch") as launch,
    ):
        response = client.post("/api/v1/discoveries", json={
            "target_type": "range", "start_ip": "10.10.0.10", "end_ip": "10.10.0.20", "authorization_confirmed": True,
        })
    assert response.status_code == 201
    target_args = build.call_args.kwargs["target_args"]
    assert target_args == ["10.10.0.10/31", "10.10.0.12/30", "10.10.0.16/30", "10.10.0.20/32"]
    assert launch.call_args.kwargs["target_args"] == target_args
    assert all(";" not in value for value in target_args)


def test_on_demand_ip_range_discovery_succeeds_without_allow_list(client: TestClient) -> None:
    with (
        patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn"]) as build,
        patch("app.api.routes.discoveries.scanner_service.launch") as launch,
    ):
        response = client.post("/api/v1/discoveries", json={
            "target_type": "range",
            "start_ip": "192.168.29.10",
            "end_ip": "192.168.29.20",
            "authorization_mode": "on_demand",
            "authorization_confirmed": True,
        })

    assert response.status_code == 201
    assert response.json()["target"] == "192.168.29.10-192.168.29.20"
    expected_args = ["192.168.29.10/31", "192.168.29.12/30", "192.168.29.16/30", "192.168.29.20/32"]
    assert build.call_args.kwargs["target_args"] == expected_args
    assert launch.call_args.kwargs["target_args"] == expected_args


def test_discovery_rejects_unconfirmed_unauthorized_and_missing_nmap(client: TestClient, db_session: Session) -> None:
    authorize(db_session, "192.0.2.0/24")
    unconfirmed = client.post("/api/v1/discoveries", json={"target_type": "cidr", "cidr": "192.0.2.0/24"})
    assert unconfirmed.status_code == 403
    unauthorized = client.post("/api/v1/discoveries", json={"target_type": "cidr", "cidr": "198.51.100.0/24", "authorization_confirmed": True})
    assert unauthorized.status_code == 403
    with patch("app.api.routes.discoveries.scanner_service._build_args", side_effect=NmapNotAvailableError("nmap missing")):
        missing = client.post("/api/v1/discoveries", json={"target_type": "cidr", "cidr": "192.0.2.0/24", "authorization_confirmed": True})
    assert missing.status_code == 503
    assert "nmap missing" in missing.json()["detail"]


def test_inventory_reports_authorization_and_preserves_optional_metadata(client: TestClient, db_session: Session) -> None:
    authorize(db_session, "203.0.113.0/24")
    run = Scan(id=uuid.uuid4(), target="203.0.113.0/24", operation="discovery", target_kind="cidr", scan_type="network", status="completed", progress=100, authorization_mode="allow_list", authorization_confirmed=True)
    db_session.add(run)
    db_session.flush()
    db_session.add(ScanResult(scan_id=run.id, host_address="203.0.113.7", host_state="up", hostname="router.lab", mac_address="00:11:22:33:44:55", vendor="Lab Vendor"))
    db_session.commit()
    response = client.get(f"/api/v1/discoveries/{run.id}/hosts")
    assert response.status_code == 200
    host = response.json()["items"][0]
    assert host["ip_address"] == "203.0.113.7"
    assert host["authorized"] is True
    assert host["mac_address"] == "00:11:22:33:44:55"
    assert host["vendor"] == "Lab Vendor"


def test_on_demand_inventory_authorizes_only_hosts_inside_recorded_scope(client: TestClient, db_session: Session) -> None:
    run = Scan(
        id=uuid.uuid4(), target="192.168.60.0/24", operation="discovery",
        target_kind="cidr", scan_type="network", status="completed", progress=100,
        authorization_mode="on_demand", authorization_confirmed=True,
    )
    db_session.add(run)
    db_session.flush()
    db_session.add_all([
        ScanResult(scan_id=run.id, host_address="192.168.60.8", host_state="up"),
        ScanResult(scan_id=run.id, host_address="198.51.100.8", host_state="up"),
    ])
    db_session.commit()

    response = client.get(f"/api/v1/discoveries/{run.id}/hosts")
    assert response.status_code == 200
    by_ip = {item["ip_address"]: item for item in response.json()["items"]}
    assert by_ip["192.168.60.8"]["authorized"] is True
    assert by_ip["198.51.100.8"]["authorized"] is False


def test_partial_results_are_persisted_without_claiming_completion(db_session: Session) -> None:
    run = Scan(id=uuid.uuid4(), target="192.168.1.0/24", operation="discovery", target_kind="cidr", scan_type="network", status="running", progress=10, authorization_mode="allow_list", authorization_confirmed=True)
    db_session.add(run)
    db_session.commit()
    summary = parse_nmap_xml("<nmaprun><host><status state='up'/><address addr='192.168.1.2' addrtype='ipv4'/></host><runstats><finished exit='error'/></runstats></nmaprun>")
    asyncio.run(NmapScannerService()._persist_results(db_session, run.id, summary, mark_completed=False, partial=True))
    db_session.refresh(run)
    assert run.status == "running"
    assert run.partial_results is True
    assert db_session.query(ScanResult).filter_by(scan_id=run.id).count() == 1


def test_no_response_discovery_does_not_fabricate_scope_as_a_host(db_session: Session) -> None:
    run = Scan(id=uuid.uuid4(), target="192.168.90.0/24", operation="discovery", target_kind="cidr", scan_type="network", status="running", progress=10, authorization_mode="allow_list", authorization_confirmed=True)
    db_session.add(run)
    db_session.commit()
    summary = parse_nmap_xml("<nmaprun><runstats><finished exit='success'/></runstats></nmaprun>")
    asyncio.run(NmapScannerService()._persist_results(db_session, run.id, summary))
    assert db_session.query(ScanResult).filter_by(scan_id=run.id).count() == 0
    assert db_session.query(Asset).filter_by(target="192.168.90.0/24").count() == 0
    db_session.refresh(run)
    assert run.status == "completed"


def test_direct_scan_endpoint_rejects_cidr_but_keeps_single_host(client: TestClient, db_session: Session) -> None:
    authorize(db_session, "198.51.100.0/24")
    cidr = client.post("/api/v1/scans", json={"target": "198.51.100.0/24", "scan_type": "network"})
    assert cidr.status_code == 422
    assert "/api/v1/discoveries" in cidr.json()["detail"]
    with (
        patch("app.api.routes.scans.scanner_service._build_args", return_value=["nmap", "-sV", "198.51.100.10"]),
        patch("app.api.routes.scans.scanner_service.launch"),
    ):
        host = client.post("/api/v1/scans", json={"target": "198.51.100.10", "scan_type": "quick"})
    assert host.status_code == 201
    assert host.json()["target"] == "198.51.100.10"


def test_cancel_discovery_marks_queued_run_cancelled(client: TestClient, db_session: Session) -> None:
    run = Scan(id=uuid.uuid4(), target="192.168.1.0/24", operation="discovery", target_kind="cidr", scan_type="network", status="queued", progress=0, authorization_mode="allow_list", authorization_confirmed=True)
    db_session.add(run)
    db_session.commit()
    with patch("app.api.routes.discoveries.scanner_service.cancel"), patch("app.api.routes.discoveries.scanner_service.get_job", return_value=None):
        response = client.post(f"/api/v1/discoveries/{run.id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


def test_discovery_routes_require_authentication(db_session: Session) -> None:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/discoveries").status_code == 401


def test_cidr_discovery_enforces_authorized_target_ownership(db_session: Session) -> None:
    owner_id = uuid.uuid4()
    other_user_id = uuid.uuid4()
    db_session.add(AuthorizedTarget(
        target="192.168.77.0/24", owner_user_id=other_user_id, is_enabled=True,
    ))
    db_session.commit()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(
        method="test", user_id=owner_id, role="user",
    )
    with TestClient(app) as owned_client:
        unauthorized = owned_client.post("/api/v1/discoveries", json={
            "target_type": "cidr", "cidr": "192.168.77.0/24", "authorization_confirmed": True,
        })
        assert unauthorized.status_code == 403

        db_session.add(AuthorizedTarget(
            target="192.168.77.0/24", owner_user_id=owner_id, is_enabled=True,
        ))
        db_session.commit()
        with (
            patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn"]),
            patch("app.api.routes.discoveries.scanner_service.launch"),
        ):
            authorized = owned_client.post("/api/v1/discoveries", json={
                "target_type": "cidr", "cidr": "192.168.77.0/24", "authorization_confirmed": True,
            })
        assert authorized.status_code == 201
        assert authorized.json()["target_kind"] == "cidr"
