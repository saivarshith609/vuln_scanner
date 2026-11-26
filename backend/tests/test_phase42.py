"""
VulnScanner — Phase 4.2 integration tests.

Covers:
- AuthorizedTarget API (CRUD, duplicate handling)
- Authorization service (CIDR containment, disabled entries, hostname policy)
- NmapScannerService (launch, cancellation, duplicate prevention, build_args)
- NmapXmlParser (valid, empty, malformed, oversized, multi-host, no-ports)
- Scan lifecycle via API (auth-gate, queued→running→completed, failed, cancelled)
- ScanResult persistence and retrieval API
- Regression coverage for all existing APIs

Tests do NOT scan real networks; subprocess is mocked throughout.
Uses isolated in-memory SQLite identical to the Phase 3 test strategy.
"""

from __future__ import annotations

import asyncio
import subprocess
import textwrap
import uuid
from collections.abc import AsyncGenerator, Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication
from app.main import create_app
from app.models.authorized_target import AuthorizedTarget
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.scanner.auth_service import (
    OnDemandAuthorizationRequiredError,
    TargetNotAuthorizedError,
    normalize_target,
    validate_on_demand_target,
    validate_target_authorized,
)
from app.scanner.nmap_env import NmapEnvironment
from app.scanner.nmap_service import NmapScannerService, _SCAN_PROFILES, _FORBIDDEN_FLAGS
from app.scanner.xml_parser import (
    NmapXmlParseError,
    NmapXmlTooLargeError,
    parse_nmap_xml,
)

# ── XML fixtures ──────────────────────────────────────────────────────────────

VALID_NMAP_XML_TWO_PORTS = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun version="7.99" args="nmap -sV -T3 -F -oX - 192.168.1.1">
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="gateway.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu Linux"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.52"/>
          </port>
        </ports>
      </host>
      <runstats>
        <finished exit="success"/>
      </runstats>
    </nmaprun>
""")

VALID_NMAP_XML_HOST_DOWN = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun version="7.99" args="nmap -sn -oX - 10.0.0.1">
      <host>
        <status state="down" reason="no-response"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
      </host>
      <runstats>
        <finished exit="success"/>
      </runstats>
    </nmaprun>
""")

VALID_NMAP_XML_NO_PORTS = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun version="7.99" args="nmap -sn -oX - 192.168.1.1">
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
      </host>
      <runstats>
        <finished exit="success"/>
      </runstats>
    </nmaprun>
""")

MALFORMED_XML = "this is not xml at all"
WRONG_ROOT_XML = "<root><child/></root>"

# ── DB fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ── AuthorizedTarget API tests ────────────────────────────────────────────────


class TestAuthorizedTargetAPI:
    """Tests for /api/v1/authorized-targets"""

    def test_list_empty(self, client: TestClient) -> None:
        r = client.get("/api/v1/authorized-targets")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_create_valid_ip(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/authorized-targets",
            json={"target": "10.0.0.1", "description": "test host"},
        )
        assert r.status_code == 201
        data = r.json()
        assert data["target"] == "10.0.0.1"
        assert data["is_enabled"] is True

    def test_create_valid_cidr(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/authorized-targets",
            json={"target": "192.168.1.5/24"},
        )
        assert r.status_code == 201
        assert r.json()["target"] == "192.168.1.0/24"

    def test_create_valid_hostname(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/authorized-targets",
            json={"target": "app.internal"},
        )
        assert r.status_code == 201

    def test_create_invalid_syntax_rejected(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/authorized-targets",
            json={"target": "$(evil command)"},
        )
        assert r.status_code == 422

    def test_create_duplicate_rejected(self, client: TestClient) -> None:
        client.post("/api/v1/authorized-targets", json={"target": "10.0.0.5"})
        r = client.post("/api/v1/authorized-targets", json={"target": "10.0.0.5"})
        assert r.status_code == 409

    def test_get_by_id(self, client: TestClient) -> None:
        create_r = client.post("/api/v1/authorized-targets", json={"target": "1.2.3.4"})
        entry_id = create_r.json()["id"]
        r = client.get(f"/api/v1/authorized-targets/{entry_id}")
        assert r.status_code == 200
        assert r.json()["target"] == "1.2.3.4"

    def test_get_not_found(self, client: TestClient) -> None:
        r = client.get(f"/api/v1/authorized-targets/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_patch_disable(self, client: TestClient) -> None:
        create_r = client.post("/api/v1/authorized-targets", json={"target": "5.5.5.5"})
        entry_id = create_r.json()["id"]
        r = client.patch(
            f"/api/v1/authorized-targets/{entry_id}",
            json={"is_enabled": False},
        )
        assert r.status_code == 200
        assert r.json()["is_enabled"] is False

    def test_delete(self, client: TestClient) -> None:
        create_r = client.post("/api/v1/authorized-targets", json={"target": "6.6.6.6"})
        entry_id = create_r.json()["id"]
        r = client.delete(f"/api/v1/authorized-targets/{entry_id}")
        assert r.status_code == 204
        r2 = client.get(f"/api/v1/authorized-targets/{entry_id}")
        assert r2.status_code == 404

    def test_enabled_only_filter(self, client: TestClient) -> None:
        r1 = client.post("/api/v1/authorized-targets", json={"target": "7.7.7.7"})
        client.patch(
            f"/api/v1/authorized-targets/{r1.json()['id']}",
            json={"is_enabled": False},
        )
        client.post("/api/v1/authorized-targets", json={"target": "8.8.8.8"})
        r = client.get("/api/v1/authorized-targets?enabled_only=true")
        targets = [i["target"] for i in r.json()["items"]]
        assert "8.8.8.8" in targets
        assert "7.7.7.7" not in targets


# ── Auth service unit tests ───────────────────────────────────────────────────


class TestAuthService:
    """Tests for validate_target_authorized()"""

    def test_exact_ip_match(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="192.168.1.1", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        result = validate_target_authorized("192.168.1.1", db_session)
        assert result == "192.168.1.1"

    def test_ip_within_cidr(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="10.0.0.0/24", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        result = validate_target_authorized("10.0.0.50", db_session)
        assert result == "10.0.0.50"

    def test_cidr_request_within_persistent_cidr_is_authorized(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="10.0.0.5/16", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        assert validate_target_authorized("10.0.2.99/24", db_session) == "10.0.2.0/24"

    def test_ip_outside_cidr_rejected(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="10.0.0.0/24", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        with pytest.raises(TargetNotAuthorizedError):
            validate_target_authorized("10.0.1.1", db_session)

    def test_disabled_entry_not_honored(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="192.168.5.5", is_enabled=False,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        with pytest.raises(TargetNotAuthorizedError):
            validate_target_authorized("192.168.5.5", db_session)

    def test_invalid_syntax_raises_value_error(self, db_session: Session) -> None:
        with pytest.raises(ValueError, match="not a valid"):
            validate_target_authorized("not a valid target!!", db_session)

    def test_hostname_not_authorized_by_ip_entry(self, db_session: Session) -> None:
        """Hostname ↔ IP cross-authorization is explicitly NOT performed."""
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="93.184.216.34", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        # 'example.com' resolves to 93.184.216.34 in reality, but we do NOT
        # perform DNS resolution to authorize it.
        with pytest.raises(TargetNotAuthorizedError):
            validate_target_authorized("example.com", db_session)

    def test_whitespace_stripped(self, db_session: Session) -> None:
        db_session.add(
            AuthorizedTarget(id=uuid.uuid4(), target="172.16.0.1", is_enabled=True,
                             created_at=datetime.now(timezone.utc))
        )
        db_session.commit()
        result = validate_target_authorized("  172.16.0.1  ", db_session)
        assert result == "172.16.0.1"

    def test_on_demand_target_requires_explicit_confirmation(self) -> None:
        with pytest.raises(OnDemandAuthorizationRequiredError, match="explicit confirmation"):
            validate_on_demand_target("192.168.29.31", False)

    def test_on_demand_target_normalizes_single_ip_and_hostname(self) -> None:
        assert validate_on_demand_target(" 2001:0db8::1 ", True) == "2001:db8::1"
        assert validate_on_demand_target(" Host.Internal ", True) == "host.internal"

    def test_on_demand_target_rejects_network_ranges(self) -> None:
        with pytest.raises(ValueError, match="one IP address or hostname"):
            validate_on_demand_target("192.168.29.0/24", True)

    @pytest.mark.parametrize("target", ["--script=unsafe", "192.168.1.1;whoami", "https://host.test/path"])
    def test_target_normalization_rejects_unsafe_or_unsupported_input(self, target: str) -> None:
        with pytest.raises(ValueError, match="not a valid"):
            normalize_target(target)


# ── NmapXmlParser tests ───────────────────────────────────────────────────────


class TestNmapXmlParser:
    """Tests for parse_nmap_xml()"""

    def test_valid_two_ports_parsed(self) -> None:
        summary = parse_nmap_xml(VALID_NMAP_XML_TWO_PORTS)
        assert summary.succeeded is True
        assert len(summary.hosts) == 1
        host = summary.hosts[0]
        assert host.address == "192.168.1.1"
        assert host.state == "up"
        assert host.hostname == "gateway.local"
        assert len(host.ports) == 2

        ssh = next(p for p in host.ports if p.portid == 22)
        assert ssh.protocol == "tcp"
        assert ssh.state == "open"
        assert ssh.service_product == "OpenSSH"
        assert ssh.service_version == "8.9"
        assert ssh.service_extra_info == "Ubuntu Linux"

        http = next(p for p in host.ports if p.portid == 80)
        assert http.service_name == "http"
        assert http.service_product == "Apache httpd"
        assert http.service_extra_info is None

    def test_host_down_recorded(self) -> None:
        summary = parse_nmap_xml(VALID_NMAP_XML_HOST_DOWN)
        assert summary.succeeded is True
        assert len(summary.hosts) == 1
        assert summary.hosts[0].state == "down"

    def test_no_ports_host_only(self) -> None:
        summary = parse_nmap_xml(VALID_NMAP_XML_NO_PORTS)
        host = summary.hosts[0]
        assert host.state == "up"
        assert host.ports == []

    def test_empty_xml_raises_parse_error(self) -> None:
        with pytest.raises(NmapXmlParseError, match="empty"):
            parse_nmap_xml(b"")

    def test_malformed_xml_raises_parse_error(self) -> None:
        with pytest.raises(NmapXmlParseError):
            parse_nmap_xml(MALFORMED_XML)

    def test_wrong_root_raises_parse_error(self) -> None:
        with pytest.raises(NmapXmlParseError, match="nmaprun"):
            parse_nmap_xml(WRONG_ROOT_XML)

    def test_oversized_raises_too_large_error(self) -> None:
        big_xml = VALID_NMAP_XML_TWO_PORTS.encode()
        with pytest.raises(NmapXmlTooLargeError, match="exceeds"):
            parse_nmap_xml(big_xml, max_bytes=10)

    def test_bytes_input_accepted(self) -> None:
        summary = parse_nmap_xml(VALID_NMAP_XML_TWO_PORTS.encode("utf-8"))
        assert summary.hosts[0].address == "192.168.1.1"

    def test_nmap_version_extracted(self) -> None:
        summary = parse_nmap_xml(VALID_NMAP_XML_TWO_PORTS)
        assert summary.nmap_version == "7.99"

    def test_exit_failure_detected(self) -> None:
        xml = VALID_NMAP_XML_TWO_PORTS.replace('exit="success"', 'exit="error"')
        summary = parse_nmap_xml(xml)
        assert summary.succeeded is False


# ── NmapScannerService unit tests ─────────────────────────────────────────────


class TestNmapScannerService:
    """Tests for NmapScannerService (subprocess mocked)."""

    def _make_service(self, executable: str = "/usr/bin/nmap") -> NmapScannerService:
        svc = NmapScannerService()
        env = NmapEnvironment(
            executable=executable,
            version_string="Nmap version 7.99",
            is_available=True,
            error="",
            probe_candidates=[executable],
        )
        svc._env = env
        svc._semaphore = asyncio.Semaphore(3)
        return svc

    def test_build_args_quick(self) -> None:
        svc = self._make_service()
        args = svc._build_args("192.168.1.1", "quick")
        assert args[0] == "/usr/bin/nmap"
        assert "-sV" in args
        assert "-F" in args
        assert "-oX" in args
        assert "-" in args
        assert "192.168.1.1" == args[-1]

    def test_build_args_network(self) -> None:
        svc = self._make_service()
        args = svc._build_args("10.0.0.0/24", "network")
        assert "-sn" in args
        assert "-oX" in args

    def test_build_args_full(self) -> None:
        svc = self._make_service()
        args = svc._build_args("10.0.0.1", "full")
        assert "-p-" in args

    def test_build_args_invalid_type_raises(self) -> None:
        svc = self._make_service()
        with pytest.raises(ValueError, match="Unsupported scan_type"):
            svc._build_args("10.0.0.1", "exploit_everything")

    def test_forbidden_flags_not_in_any_profile(self) -> None:
        """No pre-defined scan profile should contain a forbidden flag."""
        svc = self._make_service()
        for scan_type in _SCAN_PROFILES:
            args = svc._build_args("127.0.0.1", scan_type)
            for flag in args:
                for forbidden in _FORBIDDEN_FLAGS:
                    assert not flag.startswith(forbidden), (
                        f"Profile {scan_type!r} contains forbidden flag {flag!r}"
                    )

    def test_launch_without_initialize_raises(self) -> None:
        svc = NmapScannerService()  # not initialized
        with pytest.raises(RuntimeError, match="initialize"):
            svc.launch(uuid.uuid4(), "127.0.0.1", "quick")

    def test_nmap_unavailable_raises(self) -> None:
        svc = NmapScannerService()
        from app.scanner.service import NmapNotAvailableError
        svc._env = NmapEnvironment(
            executable=None,
            version_string="",
            is_available=False,
            error="nmap not found",
        )
        svc._semaphore = asyncio.Semaphore(3)
        with pytest.raises(NmapNotAvailableError):
            svc.launch(uuid.uuid4(), "127.0.0.1", "quick")

    def test_cancel_nonexistent_scan_is_noop(self) -> None:
        svc = self._make_service()
        svc.cancel(uuid.uuid4())  # should not raise

    def test_get_job_unknown_scan_returns_none(self) -> None:
        svc = self._make_service()
        assert svc.get_job(uuid.uuid4()) is None


# ── Scan API integration tests (Phase 4.2 lifecycle) ─────────────────────────


class TestScanAPIWithAuth:
    """Tests for scan lifecycle with authorization gate."""

    def _add_authorized(self, db_session: Session, target: str) -> None:
        db_session.add(
            AuthorizedTarget(
                id=uuid.uuid4(), target=target, is_enabled=True,
                created_at=datetime.now(timezone.utc),
            )
        )
        db_session.commit()

    def test_create_scan_without_authorization_returns_403(
        self, client: TestClient
    ) -> None:
        r = client.post(
            "/api/v1/scans",
            json={"target": "10.0.0.1", "scan_type": "quick"},
        )
        assert r.status_code == 403
        assert "authorized" in r.json()["detail"].lower()

    def test_create_scan_with_authorization_returns_201(
        self, client: TestClient, db_session: Session
    ) -> None:
        self._add_authorized(db_session, "10.0.0.1")
        # Mock the scanner service launch so no real nmap runs
        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            r = client.post(
                "/api/v1/scans",
                json={"target": "10.0.0.1", "scan_type": "quick"},
            )
        assert r.status_code == 201
        data = r.json()
        assert data["status"] == "queued"
        assert data["target"] == "10.0.0.1"
        assert data["progress"] == 0

    @pytest.mark.parametrize("target", ["192.168.29.31", "192.168.29.32"])
    def test_create_on_demand_scan_accepts_different_single_ips(
        self, client: TestClient, target: str
    ) -> None:
        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            response = client.post(
                "/api/v1/scans",
                json={
                    "target": target,
                    "scan_type": "quick",
                    "authorization_mode": "on_demand",
                    "authorization_confirmed": True,
                },
            )

        assert response.status_code == 201
        assert response.json()["target"] == target
        assert response.json()["status"] == "queued"

    def test_create_on_demand_scan_normalizes_hostname(
        self, client: TestClient
    ) -> None:
        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            response = client.post(
                "/api/v1/scans",
                json={
                    "target": " Host.Internal ",
                    "scan_type": "quick",
                    "authorization_mode": "on_demand",
                    "authorization_confirmed": True,
                },
            )

        assert response.status_code == 201
        assert response.json()["target"] == "host.internal"

    def test_create_on_demand_scan_without_confirmation_returns_403(
        self, client: TestClient
    ) -> None:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": "192.168.29.31",
                "scan_type": "quick",
                "authorization_mode": "on_demand",
                "authorization_confirmed": False,
            },
        )
        assert response.status_code == 403
        assert "confirmation" in response.json()["detail"].lower()

    @pytest.mark.parametrize("target", ["192.168.29.0/24", "--script=unsafe", "192.168.1.1;whoami"])
    def test_create_on_demand_scan_rejects_ranges_and_malformed_targets(
        self, client: TestClient, target: str
    ) -> None:
        response = client.post(
            "/api/v1/scans",
            json={
                "target": target,
                "scan_type": "quick",
                "authorization_mode": "on_demand",
                "authorization_confirmed": True,
            },
        )
        assert response.status_code == 422

    def test_create_scan_cidr_authorized_ip_passes(
        self, client: TestClient, db_session: Session
    ) -> None:
        self._add_authorized(db_session, "192.168.0.0/24")
        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            r = client.post(
                "/api/v1/scans",
                json={"target": "192.168.0.50", "scan_type": "network"},
            )
        assert r.status_code == 201

    def test_create_scan_disabled_entry_returns_403(
        self, client: TestClient, db_session: Session
    ) -> None:
        db_session.add(
            AuthorizedTarget(
                id=uuid.uuid4(), target="10.9.9.9", is_enabled=False,
                created_at=datetime.now(timezone.utc),
            )
        )
        db_session.commit()
        r = client.post(
            "/api/v1/scans",
            json={"target": "10.9.9.9", "scan_type": "quick"},
        )
        assert r.status_code == 403

    def test_create_scan_invalid_target_syntax_returns_422(
        self, client: TestClient
    ) -> None:
        r = client.post(
            "/api/v1/scans",
            json={"target": "not valid!! @#$", "scan_type": "quick"},
        )
        assert r.status_code == 422

    def test_cancel_queued_scan_succeeds(
        self, client: TestClient, db_session: Session
    ) -> None:
        self._add_authorized(db_session, "10.1.1.1")
        with patch.object(
            __import__("app.scanner.nmap_service", fromlist=["scanner_service"]).scanner_service,
            "launch",
            return_value=MagicMock(),
        ):
            create_r = client.post(
                "/api/v1/scans",
                json={"target": "10.1.1.1", "scan_type": "quick"},
            )
        scan_id = create_r.json()["id"]
        cancel_r = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert cancel_r.status_code == 200
        assert cancel_r.json()["status"] == "cancelled"

    def test_cancel_completed_scan_returns_400(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan = Scan(
            id=uuid.uuid4(), target="10.2.2.2", scan_type="quick",
            status="completed", progress=100,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(scan)
        db_session.commit()
        r = client.post(f"/api/v1/scans/{scan.id}/cancel")
        assert r.status_code == 400

    def test_scan_response_includes_error_message(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan = Scan(
            id=uuid.uuid4(), target="10.3.3.3", scan_type="quick",
            status="failed", progress=0,
            error_message="Nmap timed out after 600 seconds.",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(scan)
        db_session.commit()
        r = client.get(f"/api/v1/scans/{scan.id}")
        assert r.status_code == 200
        assert r.json()["error_message"] == "Nmap timed out after 600 seconds."


# ── ScanResult API tests ──────────────────────────────────────────────────────


class TestScanResultAPI:
    """Tests for /api/v1/scan-results"""

    def _seed_scan_with_results(self, db_session: Session) -> uuid.UUID:
        scan = Scan(
            id=uuid.uuid4(), target="10.5.5.5", scan_type="quick",
            status="completed", progress=100,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(scan)
        db_session.flush()

        r1 = ScanResult(
            id=uuid.uuid4(), scan_id=scan.id,
            host_address="10.5.5.5", host_state="up",
            port=22, protocol="tcp", port_state="open",
            service_name="ssh", service_product="OpenSSH", service_version="8.9",
            created_at=datetime.now(timezone.utc),
        )
        r2 = ScanResult(
            id=uuid.uuid4(), scan_id=scan.id,
            host_address="10.5.5.5", host_state="up",
            port=80, protocol="tcp", port_state="open",
            service_name="http", service_product="Apache httpd",
            created_at=datetime.now(timezone.utc),
        )
        r3 = ScanResult(
            id=uuid.uuid4(), scan_id=scan.id,
            host_address="10.5.5.5", host_state="up",
            port=443, protocol="tcp", port_state="filtered",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add_all([r1, r2, r3])
        db_session.commit()
        return scan.id

    def test_list_results_for_scan(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan_id = self._seed_scan_with_results(db_session)
        r = client.get(f"/api/v1/scan-results?scan_id={scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3

    def test_filter_by_port_state(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan_id = self._seed_scan_with_results(db_session)
        r = client.get(f"/api/v1/scan-results?scan_id={scan_id}&port_state=open")
        assert r.json()["total"] == 2

    def test_filter_by_host(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan_id = self._seed_scan_with_results(db_session)
        r = client.get(f"/api/v1/scan-results?scan_id={scan_id}&host=10.5.5.5")
        assert r.json()["total"] == 3

    def test_scan_not_found_returns_404(self, client: TestClient) -> None:
        r = client.get(f"/api/v1/scan-results?scan_id={uuid.uuid4()}")
        assert r.status_code == 404

    def test_result_fields_present(
        self, client: TestClient, db_session: Session
    ) -> None:
        scan_id = self._seed_scan_with_results(db_session)
        r = client.get(f"/api/v1/scan-results?scan_id={scan_id}&port_state=open")
        item = r.json()["items"][0]
        for field in ("id", "scan_id", "host_address", "host_state", "port",
                      "protocol", "port_state", "service_name", "service_product",
                      "service_version", "created_at"):
            assert field in item


# ── Async scan execution tests ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestNmapScannerServiceAsync:
    """
    Tests for the async scan execution path with mocked subprocess.
    All tests use asyncio.get_event_loop() via pytest-asyncio.
    """

    def _make_service(self) -> NmapScannerService:
        svc = NmapScannerService()
        env = NmapEnvironment(
            executable="/usr/bin/nmap",
            version_string="Nmap version 7.99",
            is_available=True,
            error="",
            probe_candidates=["/usr/bin/nmap"],
        )
        svc._env = env
        svc._semaphore = asyncio.Semaphore(3)
        return svc

    def _make_db(self) -> tuple[Session, uuid.UUID]:
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        session = factory()
        scan_id = uuid.uuid4()
        scan = Scan(
            id=scan_id, target="192.168.1.1", scan_type="quick",
            status="queued", progress=0,
            created_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        session.commit()
        return session, scan_id

    def _mock_process(
        self,
        stdout: bytes = VALID_NMAP_XML_TWO_PORTS.encode(),
        returncode: int = 0,
    ) -> AsyncMock:
        proc = AsyncMock()
        proc.returncode = returncode
        proc.communicate.return_value = (stdout, b"")
        proc.terminate = MagicMock()
        proc.kill = MagicMock()
        proc.wait = AsyncMock(return_value=returncode)
        proc.pid = 12345
        return proc

    async def test_successful_scan_marks_completed(self) -> None:
        svc = self._make_service()
        session, scan_id = self._make_db()
        proc = self._mock_process()

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await svc._run_scan(
                    scan_id,
                    "192.168.1.1",
                    ["/usr/bin/nmap", "-sV", "-T3", "-F", "-oX", "-", "192.168.1.1"],
                    timeout_seconds=30,
                )

        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "completed"
        assert scan.progress == 100
        assert scan.started_at is not None
        assert scan.completed_at is not None

        results = session.query(ScanResult).filter_by(scan_id=scan_id).all()
        assert len(results) == 2  # two ports

    async def test_nmap_nonzero_exit_marks_failed(self) -> None:
        svc = self._make_service()
        session, scan_id = self._make_db()
        proc = self._mock_process(stdout=b"", returncode=1)

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await svc._run_scan(
                    scan_id, "192.168.1.1",
                    ["/usr/bin/nmap", "-F", "-oX", "-", "192.168.1.1"],
                    timeout_seconds=30,
                )

        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"
        assert scan.error_message is not None
        assert "exit" in scan.error_message.lower()

    async def test_malformed_xml_marks_failed(self) -> None:
        svc = self._make_service()
        session, scan_id = self._make_db()
        proc = self._mock_process(stdout=b"not xml at all", returncode=0)

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await svc._run_scan(
                    scan_id, "192.168.1.1",
                    ["/usr/bin/nmap", "-F", "-oX", "-", "192.168.1.1"],
                    timeout_seconds=30,
                )

        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"

    async def test_oversized_output_marks_failed(self) -> None:
        svc = self._make_service()
        session, scan_id = self._make_db()
        big_output = b"x" * (11 * 1024 * 1024)  # 11 MiB > 10 MiB limit
        proc = self._mock_process(stdout=big_output, returncode=0)

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await svc._run_scan(
                    scan_id, "192.168.1.1",
                    ["/usr/bin/nmap", "-F", "-oX", "-", "192.168.1.1"],
                    timeout_seconds=30,
                )

        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"
        assert "too large" in (scan.error_message or "").lower()

    async def test_timeout_marks_failed(self) -> None:
        svc = self._make_service()
        session, scan_id = self._make_db()

        async def slow_communicate() -> tuple[bytes, bytes]:
            await asyncio.sleep(100)
            return b"", b""

        proc = AsyncMock()
        proc.returncode = None
        proc.communicate.side_effect = slow_communicate
        proc.terminate = MagicMock()
        proc.kill = MagicMock()
        proc.wait = AsyncMock(return_value=None)
        proc.pid = 99999

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                # Use very short timeout to trigger it quickly
                await svc._run_scan(
                    scan_id, "192.168.1.1",
                    ["/usr/bin/nmap", "-F", "-oX", "-", "192.168.1.1"],
                    timeout_seconds=1,
                )

        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan.status == "failed"
        assert "timed out" in (scan.error_message or "").lower()

    async def test_duplicate_launch_raises_runtime_error(self) -> None:
        svc = self._make_service()

        async def never_finish() -> None:
            await asyncio.sleep(3600)

        # Fake a running task
        loop = asyncio.get_event_loop()
        task = loop.create_task(never_finish())
        scan_id = uuid.uuid4()
        svc._tasks[scan_id] = task

        try:
            with pytest.raises(RuntimeError, match="already running"):
                svc.launch(scan_id, "10.0.0.1", "quick")
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def test_host_down_persisted_as_result(self) -> None:
        """Host-down records should still be written to scan_results."""
        svc = self._make_service()
        session, scan_id = self._make_db()
        proc = self._mock_process(
            stdout=VALID_NMAP_XML_HOST_DOWN.encode(), returncode=0
        )

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch("asyncio.create_subprocess_exec", return_value=proc):
                await svc._run_scan(
                    scan_id, "10.0.0.1",
                    ["/usr/bin/nmap", "-sn", "-oX", "-", "10.0.0.1"],
                    timeout_seconds=30,
                )

        session.expire_all()
        results = session.query(ScanResult).filter_by(scan_id=scan_id).all()
        assert len(results) == 1
        assert results[0].host_state == "down"

    async def test_selector_event_loop_not_implemented_fallback_to_popen(self) -> None:
        """
        Regression test: On Windows with Uvicorn --reload, the loop policy is
        WindowsSelectorEventLoopPolicy, which causes asyncio.create_subprocess_exec
        to raise NotImplementedError. The scanner must fall back to managed Popen
        and complete the scan successfully.
        """
        svc = self._make_service()
        session, scan_id = self._make_db()

        mock_popen = MagicMock()
        mock_popen.returncode = 0
        mock_popen.communicate.return_value = (
            VALID_NMAP_XML_TWO_PORTS.encode("utf-8"),
            b"",
        )
        mock_popen.wait.return_value = 0
        mock_popen.pid = 54321

        with patch("app.scanner.nmap_service.get_session_factory", return_value=lambda: session):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=NotImplementedError("WindowsSelectorEventLoop does not support subprocesses"),
            ):
                with patch("subprocess.Popen", return_value=mock_popen) as mock_popen_ctor:
                    await svc._run_scan(
                        scan_id,
                        "192.168.1.1",
                        ["/usr/bin/nmap", "-sV", "-T3", "-F", "-oX", "-", "192.168.1.1"],
                        timeout_seconds=30,
                    )

        mock_popen_ctor.assert_called_once()
        session.expire_all()
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "completed"
        assert scan.progress == 100
        assert scan.completed_at is not None

        results = session.query(ScanResult).filter_by(scan_id=scan_id).all()
        assert len(results) == 2


# ── Regression: existing API tests ───────────────────────────────────────────


class TestRegressionExistingAPIs:
    """Ensure all Phase 3 APIs still work after Phase 4.2 changes."""

    def test_health_endpoint(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_root_endpoint(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        assert "VulnScanner" in r.json()["message"]

    def test_assets_create_and_list(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/assets",
            json={"name": "Test Server", "asset_type": "server", "target": "10.0.0.1"},
        )
        assert r.status_code == 201
        r2 = client.get("/api/v1/assets")
        assert r2.json()["total"] == 1

    def test_scans_list_empty(self, client: TestClient) -> None:
        r = client.get("/api/v1/scans")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_vulnerabilities_list_empty(self, client: TestClient) -> None:
        r = client.get("/api/v1/vulnerabilities")
        assert r.status_code == 200

    def test_dashboard_returns_zeros(self, client: TestClient) -> None:
        r = client.get("/api/v1/dashboard")
        assert r.status_code == 200
        data = r.json()
        assert data["total_assets"] == 0
        assert data["total_scans"] == 0
