"""Browser detection and login activity tracking tests."""

from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.passwords import hash_password
from app.core.user_agent import parse_user_agent
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.login_activity import LoginActivity
from app.models.user import User

PASSWORD = "StrongPassword!42"


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
    with TestClient(app) as test_client:
        yield test_client


def _make_user(db: Session, username: str, *, role: str = "user") -> User:
    user = User(
        full_name=f"{username} Account",
        username=username,
        email=f"{username.lower()}@example.test",
        password_hash=hash_password(PASSWORD),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return user


def test_parse_user_agent_browsers_os_and_devices() -> None:
    chrome = parse_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    assert (chrome.browser_name, chrome.browser_version, chrome.operating_system, chrome.os_version, chrome.device_type) == (
        "Chrome", "131", "Windows", "10/11", "Desktop"
    )

    firefox = parse_user_agent(
        "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
    )
    assert (firefox.browser_name, firefox.browser_version, firefox.operating_system, firefox.device_type) == (
        "Firefox", "132", "Linux", "Desktop"
    )

    edge = parse_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.51"
    )
    assert (edge.browser_name, edge.browser_version, edge.operating_system, edge.device_type) == (
        "Edge", "131", "Windows", "Desktop"
    )

    safari = parse_user_agent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
    )
    assert (safari.browser_name, safari.browser_version, safari.operating_system, safari.os_version, safari.device_type) == (
        "Safari", "18", "macOS", "14.6.1", "Desktop"
    )

    mobile = parse_user_agent(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
    )
    assert (mobile.browser_name, mobile.browser_version, mobile.operating_system, mobile.os_version, mobile.device_type) == (
        "Chrome", "130", "Android", "14", "Mobile"
    )

    ios_mobile = parse_user_agent(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    )
    assert (ios_mobile.browser_name, ios_mobile.browser_version, ios_mobile.operating_system, ios_mobile.os_version, ios_mobile.device_type) == (
        "Safari", "17", "iOS", "17.5", "Mobile"
    )

    unknown = parse_user_agent("CustomProbeAgent/9.9")
    assert (unknown.browser_name, unknown.browser_version, unknown.operating_system, unknown.device_type) == (
        "Unknown", None, "Unknown", "Unknown"
    )

    missing = parse_user_agent(None)
    assert (missing.browser_name, missing.browser_version, missing.operating_system, missing.device_type) == (
        "Unknown", None, "Unknown", "Unknown"
    )


def test_login_records_success_failure_and_admin_activity_with_rbac(client: TestClient, db_session: Session) -> None:
    normal_user = _make_user(db_session, "Alice_1", role="user")
    admin_user = _make_user(db_session, "Admin_1", role="admin")

    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    firefox_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"

    # Unauthenticated access is 401
    assert client.get("/api/v1/admin/login-activity").status_code == 401

    # Failed unknown-user attempt
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "Missing_1", "password": PASSWORD},
        headers={"User-Agent": firefox_ua},
    ).status_code == 401

    # Failed wrong-password attempt for existing user
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "Alice_1", "password": "WrongPassword!1"},
        headers={"User-Agent": chrome_ua},
    ).status_code == 401

    # Successful normal user login
    assert client.post(
        "/api/v1/auth/login",
        json={"identifier": "Alice_1", "password": PASSWORD},
        headers={"User-Agent": chrome_ua},
    ).status_code == 200

    # Normal user cannot access login-activity endpoint
    assert client.get("/api/v1/admin/login-activity").status_code == 403

    # Successful admin login
    client.cookies.clear()
    assert client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "Admin_1", "password": PASSWORD},
        headers={"User-Agent": firefox_ua},
    ).status_code == 200

    # Admin can list and filter login activity (latest first)
    all_res = client.get("/api/v1/admin/login-activity")
    assert all_res.status_code == 200
    payload = all_res.json()
    assert payload["total"] == 4
    assert payload["items"][0]["username"] == "Admin_1"
    assert payload["items"][0]["browser_name"] == "Firefox"
    assert payload["items"][0]["login_status"] == "success"

    # Filter by browser & status & username search
    chrome_success = client.get("/api/v1/admin/login-activity?browser=Chrome&status=success&search=Alice")
    assert chrome_success.status_code == 200
    assert chrome_success.json()["total"] == 1
    assert chrome_success.json()["items"][0]["user_id"] == str(normal_user.id)

    unknown_failed = client.get("/api/v1/admin/login-activity?search=Missing_1&status=failed")
    assert unknown_failed.status_code == 200
    assert unknown_failed.json()["total"] == 1
    assert unknown_failed.json()["items"][0]["user_id"] is None

    # Date filtering
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    empty_future = client.get("/api/v1/admin/login-activity", params={"date_from": future})
    assert empty_future.status_code == 200
    assert empty_future.json()["total"] == 0

    # Confirm DB persistence & absence of raw UA or credentials
    rows = db_session.scalars(select(LoginActivity)).all()
    assert len(rows) == 4
    assert any(r.user_id == admin_user.id and r.login_status == "success" for r in rows)
    assert all("AppleWebKit" not in repr(r.__dict__) for r in rows)
