"""Persistent account, password-session, CSRF, and ownership regression tests."""

import uuid
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.passwords import hash_password, verify_password
from app.cli import provision_initial_api_key
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.report import Report
from app.models.scan import Scan
from app.models.platform_setting import OperatorSession
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


def registration_payload(username="Alice_1", email="alice@example.com") -> dict[str, str]:
    return {"full_name": "Alice Operator", "username": username, "email": email, "password": PASSWORD, "confirm_password": PASSWORD}


def register_and_login(client: TestClient, db_session: Session, username="Alice_1", email="alice@example.com") -> User:
    assert client.post("/api/v1/auth/register", json=registration_payload(username, email)).status_code == 201
    assert client.post("/api/v1/auth/login", json={"identifier": username, "password": PASSWORD}).status_code == 200
    return db_session.scalar(select(User).where(User.username == username))


def make_database_user(
    db_session: Session,
    username: str,
    *,
    role: str = "user",
    active: bool = True,
    password_change_required: bool = False,
) -> User:
    user = User(
        full_name=f"{username.title()} Account",
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password(PASSWORD),
        role=role,
        is_active=active,
        password_change_required=password_change_required,
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_registration_persists_normalized_user_and_argon2id_hash(client: TestClient, db_session: Session) -> None:
    payload = registration_payload("Alice.User1", "Alice@Example.COM") | {"role": "admin"}
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    assert response.json()["username"] == "Alice.User1"
    assert response.json()["email"] == "alice@example.com"
    assert response.json()["role"] == "user"
    assert "password" not in response.text.lower()
    stored = db_session.scalar(select(User).where(User.username == "Alice.User1"))
    assert stored is not None
    assert stored.password_hash != PASSWORD
    assert stored.password_hash.startswith("$argon2id$")
    assert verify_password(PASSWORD, stored.password_hash)


def test_login_by_username_or_email_restores_safe_session(client: TestClient, db_session: Session) -> None:
    assert client.post("/api/v1/auth/register", json=registration_payload()).status_code == 201
    login = client.post("/api/v1/auth/login", json={"identifier": "ALICE@EXAMPLE.COM", "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["user"]["username"] == "Alice_1"
    assert "httponly" in login.headers["set-cookie"].lower()
    assert client.cookies.get("vulnscanner_csrf")
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None and stored_session.csrf_digest
    restored = client.get("/api/v1/auth/session")
    assert restored.status_code == 200
    assert restored.json()["user"]["email"] == "alice@example.com"


def test_administrator_login_uses_database_credentials_and_restores_session(
    client: TestClient, db_session: Session,
) -> None:
    administrator = make_database_user(db_session, "security-admin", role="admin")

    login = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": administrator.email.upper(), "password": PASSWORD},
    )

    assert login.status_code == 200
    assert login.json()["user"]["id"] == str(administrator.id)
    assert login.json()["user"]["role"] == "admin"
    assert "httponly" in login.headers["set-cookie"].lower()
    assert client.get("/api/v1/auth/session").json()["user"]["role"] == "admin"
    assert client.get("/api/v1/admin/overview").status_code == 200


def test_normal_login_rejects_administrator_credentials_without_creating_a_session(
    client: TestClient, db_session: Session,
) -> None:
    administrator = make_database_user(db_session, "security-admin", role="admin")

    rejected = client.post(
        "/api/v1/auth/login",
        json={"identifier": administrator.username, "password": PASSWORD},
    )

    assert rejected.status_code == 403
    assert rejected.json()["detail"] == "Use the administrator sign-in form for this account."
    assert client.get("/api/v1/auth/session").status_code == 401
    assert db_session.scalar(select(OperatorSession)) is None


def test_role_mismatch_revokes_an_existing_privileged_session(
    client: TestClient, db_session: Session,
) -> None:
    administrator = make_database_user(db_session, "security-admin", role="admin")
    assert client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": administrator.username, "password": PASSWORD},
    ).status_code == 200
    assert client.get("/api/v1/admin/overview").status_code == 200

    rejected = client.post(
        "/api/v1/auth/login",
        json={"identifier": administrator.username, "password": PASSWORD},
    )

    assert rejected.status_code == 403
    assert client.get("/api/v1/auth/session").status_code == 401
    assert client.get("/api/v1/admin/overview").status_code == 401


def test_administrator_login_rejects_invalid_inactive_and_non_admin_accounts(
    client: TestClient, db_session: Session,
) -> None:
    make_database_user(db_session, "active-admin", role="admin")
    make_database_user(db_session, "inactive-admin", role="admin", active=False)
    make_database_user(db_session, "ordinary-user")

    invalid = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "active-admin", "password": "WrongPassword!42"},
    )
    assert invalid.status_code == 401
    assert invalid.json()["detail"] == "Invalid username/email or password."

    inactive = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "inactive-admin", "password": PASSWORD},
    )
    assert inactive.status_code == 403
    assert inactive.json()["detail"] == "Administrator account is inactive."

    ordinary = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "ordinary-user", "password": PASSWORD},
    )
    assert ordinary.status_code == 403
    assert ordinary.json()["detail"] == "Administrator privileges are required."
    assert client.get("/api/v1/auth/session").status_code == 401


def test_administrator_temporary_password_still_blocks_control_center(
    client: TestClient, db_session: Session,
) -> None:
    make_database_user(
        db_session,
        "reset-admin",
        role="admin",
        password_change_required=True,
    )
    login = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "reset-admin", "password": PASSWORD},
    )
    assert login.status_code == 200
    assert login.json()["user"]["credential_change_required"] is True
    blocked = client.get("/api/v1/admin/overview")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Password change required"


@pytest.mark.parametrize("payload", [
    registration_payload("Alice_1", "not-an-email"),
    registration_payload("alice_1", "alice@example.com"),   # first char lowercase
    registration_payload("Ab_1!", "alice@example.com"),     # fewer than 6 chars
    registration_payload("Alice_!", "alice@example.com"),   # missing number
    registration_payload("Alice12", "alice@example.com"),   # missing special char
    registration_payload("Alice 1!", "alice@example.com"),  # contains space
    registration_payload() | {"password": "weak", "confirm_password": "weak"},
    registration_payload() | {"password": "Ab1!x", "confirm_password": "Ab1!x"},
    registration_payload() | {"password": "Abcdefghij123456789!x", "confirm_password": "Abcdefghij123456789!x"},  # 21 chars
    registration_payload() | {"password": "abcdef1!", "confirm_password": "abcdef1!"},
    registration_payload() | {"password": "ABCDEF1!", "confirm_password": "ABCDEF1!"},
    registration_payload() | {"password": "Abcdef!", "confirm_password": "Abcdef!"},
    registration_payload() | {"password": "Abcdef1", "confirm_password": "Abcdef1"},
    registration_payload() | {"password": "Abcdef1 ", "confirm_password": "Abcdef1 "},  # space alone is not a special char
    registration_payload() | {"confirm_password": "DifferentPassword!42"},
])
def test_registration_validation_rejects_invalid_input(client: TestClient, payload: dict[str, str]) -> None:
    assert client.post("/api/v1/auth/register", json=payload).status_code == 422


@pytest.mark.parametrize("username", ["ALICE_1", "Alice_1", "A1!XYZ"])
def test_registration_accepts_valid_usernames_including_uppercase_only(client: TestClient, username: str) -> None:
    resp = client.post("/api/v1/auth/register", json=registration_payload(username, f"{username.lower()}@example.com"))
    assert resp.status_code == 201
    assert resp.json()["username"] == username


def test_registration_and_login_preserve_spaces_and_boundary_lengths_in_passwords(client: TestClient) -> None:
    # Exactly 6 chars, 20 chars, and leading/middle/trailing spaces
    for idx, pwd in enumerate(["Abc1!x", "Abcdefghij12345678!x", " Ab1!x "]):
        uname = f"User_{idx}!"
        email = f"user{idx}@example.com"
        reg = client.post(
            "/api/v1/auth/register",
            json=registration_payload(uname, email) | {"password": pwd, "confirm_password": pwd},
        )
        assert reg.status_code == 201
        login = client.post("/api/v1/auth/login", json={"identifier": uname, "password": pwd})
        assert login.status_code == 200
        # Trimmed version must NOT match a password with leading/trailing spaces
        if pwd != pwd.strip():
            client.cookies.clear()
            bad_login = client.post("/api/v1/auth/login", json={"identifier": uname, "password": pwd.strip()})
            assert bad_login.status_code == 401


def test_existing_legacy_user_can_still_log_in(client: TestClient, db_session: Session) -> None:
    make_database_user(db_session, "legacy_user")
    login = client.post("/api/v1/auth/login", json={"identifier": "legacy_user", "password": PASSWORD})
    assert login.status_code == 200
    assert login.json()["user"]["username"] == "legacy_user"


def test_registration_and_password_change_accept_six_character_strong_password(client: TestClient) -> None:
    six_char = "Abc1!x"
    reg = client.post(
        "/api/v1/auth/register",
        json=registration_payload("SixUser_1", "sixuser@example.com") | {"password": six_char, "confirm_password": six_char},
    )
    assert reg.status_code == 201
    login = client.post("/api/v1/auth/login", json={"identifier": "SixUser_1", "password": six_char})
    assert login.status_code == 200
    csrf = client.cookies.get("vulnscanner_csrf")
    changed = client.post(
        "/api/v1/auth/change-password",
        headers={"X-CSRF-Token": csrf or ""},
        json={"current_password": six_char, "new_password": " Zyx9@w ", "confirm_password": " Zyx9@w "},
    )
    assert changed.status_code == 200
    assert changed.json()["changed"] is True


def test_duplicate_username_and_email_are_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/auth/register", json=registration_payload()).status_code == 201
    assert client.post("/api/v1/auth/register", json=registration_payload("Alice_1", "other@example.com")).status_code == 409
    assert client.post("/api/v1/auth/register", json=registration_payload("Other_1", "alice@example.com")).status_code == 409


def test_database_unique_constraints_close_registration_race(db_session: Session) -> None:
    first = User(full_name="First", username="race", email="first@example.com", password_hash="hash", role="user", is_active=True)
    second = User(full_name="Second", username="race", email="second@example.com", password_hash="hash", role="user", is_active=True)
    db_session.add(first)
    db_session.commit()
    db_session.add(second)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
    assert len(db_session.scalars(select(User).where(User.username == "race")).all()) == 1


def test_database_failure_never_returns_registration_success(client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(db_session, "commit", lambda: (_ for _ in ()).throw(SQLAlchemyError("database unavailable")))
    response = client.post("/api/v1/auth/register", json=registration_payload())
    assert response.status_code == 503
    assert response.json()["detail"] == "Account registration is temporarily unavailable."


def test_wrong_password_and_disabled_account_use_generic_failure(client: TestClient, db_session: Session) -> None:
    assert client.post("/api/v1/auth/register", json=registration_payload()).status_code == 201
    wrong = client.post("/api/v1/auth/login", json={"identifier": "Alice_1", "password": "WrongPassword!42"})
    assert wrong.status_code == 401
    user = db_session.scalar(select(User).where(User.username == "Alice_1"))
    user.is_active = False
    db_session.commit()
    disabled = client.post("/api/v1/auth/login", json={"identifier": "Alice_1", "password": PASSWORD})
    assert disabled.status_code == 401
    assert disabled.json()["detail"] == wrong.json()["detail"]


def test_logout_revokes_session_but_preserves_account(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": client.cookies.get("vulnscanner_csrf")}).status_code == 204
    assert client.get("/api/v1/auth/session").status_code == 401
    assert db_session.scalar(select(User).where(User.username == "Alice_1")) is not None


def test_cookie_state_changes_require_csrf_token(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    payload = {"name": "Owned host", "asset_type": "server", "target": "192.0.2.10"}
    assert client.post("/api/v1/assets", json=payload).status_code == 403
    csrf = client.cookies.get("vulnscanner_csrf")
    assert csrf
    assert client.post("/api/v1/assets", json=payload, headers={"X-CSRF-Token": csrf}).status_code == 201


def test_invalid_or_mismatched_csrf_tokens_are_rejected(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    payload = {"name": "Owned host", "asset_type": "server", "target": "192.0.2.11"}
    valid_csrf = client.cookies.get("vulnscanner_csrf")
    assert valid_csrf

    invalid_header = client.post("/api/v1/assets", json=payload, headers={"X-CSRF-Token": "not-the-session-token"})
    assert invalid_header.status_code == 403
    assert invalid_header.json()["detail"] == "CSRF validation failed"

    client.cookies.delete("vulnscanner_csrf")
    client.cookies.set("vulnscanner_csrf", "stale-cookie-token")
    mismatched_cookie = client.post(
        "/api/v1/assets", json=payload, headers={"X-CSRF-Token": "stale-cookie-token"},
    )
    assert mismatched_cookie.status_code == 403
    assert mismatched_cookie.json()["detail"] == "CSRF validation failed"


def test_session_restore_initializes_missing_or_legacy_csrf_token(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None
    stored_session.csrf_digest = None
    db_session.commit()
    client.cookies.delete("vulnscanner_csrf")

    restored = client.get("/api/v1/auth/session")
    assert restored.status_code == 200
    restored_csrf = client.cookies.get("vulnscanner_csrf")
    assert restored_csrf
    db_session.refresh(stored_session)
    assert stored_session.csrf_digest is not None

    payload = {"name": "Restored session host", "asset_type": "server", "target": "192.0.2.12"}
    assert client.post(
        "/api/v1/assets", json=payload, headers={"X-CSRF-Token": restored_csrf},
    ).status_code == 201


def test_session_rotation_and_logout_invalidate_stale_tokens(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    old_session = client.cookies.get("vulnscanner_session")
    old_csrf = client.cookies.get("vulnscanner_csrf")
    assert old_session and old_csrf

    rotated = client.post("/api/v1/auth/login", json={"identifier": "Alice_1", "password": PASSWORD})
    assert rotated.status_code == 200
    new_session = client.cookies.get("vulnscanner_session")
    new_csrf = client.cookies.get("vulnscanner_csrf")
    assert new_session and new_csrf
    assert (new_session, new_csrf) != (old_session, old_csrf)

    client.cookies.clear()
    client.cookies.set("vulnscanner_session", old_session)
    client.cookies.set("vulnscanner_csrf", old_csrf)
    assert client.get("/api/v1/auth/session").status_code == 401

    client.cookies.clear()
    client.cookies.set("vulnscanner_session", new_session)
    client.cookies.set("vulnscanner_csrf", new_csrf)
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": new_csrf}).status_code == 204
    client.cookies.set("vulnscanner_session", new_session)
    client.cookies.set("vulnscanner_csrf", new_csrf)
    assert client.get("/api/v1/auth/session").status_code == 401


def test_authenticated_csrf_validated_cidr_discovery(client: TestClient, db_session: Session) -> None:
    user = register_and_login(client, db_session)
    csrf = client.cookies.get("vulnscanner_csrf")
    assert csrf

    with (
        patch("app.api.routes.discoveries.scanner_service._build_args", return_value=["nmap", "-sn"]),
        patch("app.api.routes.discoveries.scanner_service.launch") as launch,
    ):
        response = client.post("/api/v1/discoveries", json={
            "target_type": "cidr",
            "cidr": "192.168.29.31/24",
            "authorization_mode": "on_demand",
            "authorization_confirmed": True,
        }, headers={"X-CSRF-Token": csrf})

    assert response.status_code == 201
    assert response.json()["target"] == "192.168.29.0/24"
    assert response.json()["authorization_mode"] == "on_demand"
    stored = db_session.get(Scan, uuid.UUID(response.json()["id"]))
    assert stored is not None and stored.owner_user_id == user.id
    assert launch.call_args.kwargs["target_args"] == ["192.168.29.0/24"]


def test_csrf_valid_request_still_rejects_unauthorized_cidr(client: TestClient, db_session: Session) -> None:
    register_and_login(client, db_session)
    csrf = client.cookies.get("vulnscanner_csrf")
    response = client.post("/api/v1/discoveries", json={
        "target_type": "cidr",
        "cidr": "198.51.100.0/24",
        "authorization_confirmed": True,
    }, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 403
    assert "authorized allow-list" in response.json()["detail"]


def test_user_cannot_access_other_or_legacy_scans_and_reports(client: TestClient, db_session: Session) -> None:
    alice = register_and_login(client, db_session)
    bob = User(full_name="Bob", username="bob", email="bob@example.com", password_hash="unused", role="user", is_active=True)
    db_session.add(bob)
    db_session.flush()
    own_scan = Scan(owner_user_id=alice.id, target="192.0.2.1", scan_type="quick", status="completed", progress=100)
    other_scan = Scan(owner_user_id=bob.id, target="192.0.2.2", scan_type="quick", status="completed", progress=100)
    legacy_scan = Scan(target="192.0.2.3", scan_type="quick", status="completed", progress=100)
    other_report = Report(owner_user_id=bob.id, name="Bob report", target="192.0.2.2", report_type="technical", format="pdf", status="ready", scan_date="2026-10-28", file_size="1 KB")
    db_session.add_all([own_scan, other_scan, legacy_scan, other_report])
    db_session.commit()
    assert client.get(f"/api/v1/scans/{own_scan.id}").status_code == 200
    assert client.get(f"/api/v1/scans/{other_scan.id}").status_code == 404
    assert client.get(f"/api/v1/scans/{legacy_scan.id}").status_code == 404
    assert client.get(f"/api/v1/reports/{other_report.id}").status_code == 404
    assert client.get(f"/api/v1/reports/{other_report.id}/export").status_code == 404
    csrf = client.cookies.get("vulnscanner_csrf")
    assert client.post(f"/api/v1/scans/{other_scan.id}/cancel", headers={"X-CSRF-Token": csrf}).status_code == 404
    assert client.get("/api/v1/settings").status_code == 403

    admin_key = provision_initial_api_key(db_session)
    assert client.get(f"/api/v1/scans/{other_scan.id}", headers={"X-API-Key": admin_key}).status_code == 200
    assert client.get(f"/api/v1/scans/{legacy_scan.id}", headers={"X-API-Key": admin_key}).status_code == 200


def test_registered_account_survives_new_browser_client(db_session: Session) -> None:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as first:
        assert first.post("/api/v1/auth/register", json=registration_payload()).status_code == 201
    with TestClient(app) as restarted:
        assert restarted.post("/api/v1/auth/login", json={"identifier": "Alice_1", "password": PASSWORD}).status_code == 200
