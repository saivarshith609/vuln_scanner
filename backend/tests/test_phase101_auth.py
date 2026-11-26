"""Phase 10.1 API-key authentication and inactivity-session tests."""

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
import re
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.cli import create_initial_administrator, main as cli_main, reset_administrator_password
from app.cli import provision_initial_api_key, rotate_platform_api_key
from app.core.auth import authenticate_api_key, create_operator_session, create_user_session
from app.core.config import get_settings
from app.core.passwords import hash_password, verify_password
from app.core.secrets import verify_api_key
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit_log import AuditLog
from app.models.platform_setting import OperatorSession, PlatformApiKey, PlatformSetting
from app.models.user import User


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    session.add(PlatformSetting(id=1, session_timeout_minutes=30))
    session.commit()
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
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_production_requires_secure_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="SESSION_COOKIE_SECURE=true"):
            create_app()
    finally:
        get_settings.cache_clear()


def test_initial_provisioning_is_local_one_time_and_stores_only_verifier(db_session: Session) -> None:
    raw_key = provision_initial_api_key(db_session)
    stored = db_session.get(PlatformApiKey, 1)
    assert stored is not None
    assert raw_key.encode() not in stored.key_hash
    assert verify_api_key(raw_key, stored.key_hash, stored.hash_salt)
    with pytest.raises(RuntimeError, match="already exists"):
        provision_initial_api_key(db_session)


def test_initial_admin_cli_creates_one_hashed_audited_database_administrator(
    client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    password = "Initial!Admin42"
    answers = iter(["Security Administrator", "Security.Admin1", "ADMIN@EXAMPLE.TEST", "CREATE"])
    password_answers = iter([password, password])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(password_answers))
    monkeypatch.setattr("app.cli.get_session_factory", lambda: lambda: db_session)
    monkeypatch.setattr(sys, "argv", ["vuln", "create-admin"])

    cli_main()

    output = capsys.readouterr().out
    administrator = db_session.scalar(select(User).where(User.username == "Security.Admin1"))
    assert administrator is not None
    assert administrator.email == "admin@example.test"
    assert administrator.role == "admin"
    assert administrator.is_active is True
    assert administrator.password_hash.startswith("$argon2id$")
    assert verify_password(password, administrator.password_hash)
    assert password not in output
    assert password not in caplog.text
    event = db_session.scalar(select(AuditLog).where(AuditLog.event_type == "admin.account_provisioned"))
    assert event is not None
    assert event.resource_id == str(administrator.id)
    assert password not in str(event.metadata_json)

    login = client.post(
        "/api/v1/auth/admin/login",
        json={"identifier": "Security.Admin1", "password": password},
    )
    assert login.status_code == 200
    assert login.json()["user"]["id"] == str(administrator.id)
    assert login.json()["user"]["role"] == "admin"
    assert client.get("/api/v1/auth/session").json()["user"]["role"] == "admin"
    assert client.get("/api/v1/admin/overview").status_code == 200


def test_initial_admin_provisioning_rejects_duplicate_identity_and_second_cli_use(
    db_session: Session,
) -> None:
    existing = User(
        full_name="Existing User",
        username="Existing_1",
        email="existing@example.test",
        password_hash=hash_password("Existing!Pass42"),
        role="user",
        is_active=True,
    )
    db_session.add(existing)
    db_session.commit()

    with pytest.raises(RuntimeError, match="username already exists"):
        create_initial_administrator(
            db_session,
            full_name="Duplicate Username",
            username="Existing_1",
            email="unique@example.test",
            password="Initial!Admin42",
        )
    with pytest.raises(RuntimeError, match="email already exists"):
        create_initial_administrator(
            db_session,
            full_name="Duplicate Email",
            username="Unique-Admin1",
            email="existing@example.test",
            password="Initial!Admin42",
        )

    existing.role = "admin"
    db_session.commit()
    existing_hash = existing.password_hash
    dedicated = create_initial_administrator(
        db_session,
        full_name="Dedicated Administrator",
        username="Dedicated-Admin1",
        email="dedicated@example.test",
        password="Initial!Admin42",
    )
    db_session.refresh(existing)
    assert dedicated.role == "admin"
    assert existing.role == "admin"
    assert existing.password_hash == existing_hash

    with pytest.raises(RuntimeError, match="one-time create-admin bootstrap has already been used"):
        create_initial_administrator(
            db_session,
            full_name="Another Administrator",
            username="Another-Admin1",
            email="another@example.test",
            password="Initial!Admin42",
        )


def test_initial_admin_cli_password_mismatch_makes_no_database_change(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    answers = iter(["Security Administrator", "security-admin", "admin@example.test"])
    password_answers = iter(["Initial!Administrator42", "Different!Password42"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(password_answers))
    monkeypatch.setattr(
        "app.cli.get_session_factory",
        lambda: (_ for _ in ()).throw(AssertionError("database should not open")),
    )
    monkeypatch.setattr(sys, "argv", ["vuln", "create-admin"])

    cli_main()

    assert "password confirmation does not match" in capsys.readouterr().out


def test_local_admin_password_reset_preserves_identity_revokes_sessions_and_audits(
    db_session: Session,
) -> None:
    administrator = User(
        full_name="Dedicated Administrator",
        username="database_admin",
        email="admin@example.test",
        password_hash=hash_password("Old!Password42"),
        role="admin",
        is_active=True,
        password_change_required=True,
        version=4,
    )
    db_session.add(administrator)
    db_session.commit()
    old_hash = administrator.password_hash
    session_token, operator_session, _ = create_user_session(db_session, administrator)

    reset = reset_administrator_password(
        db_session,
        identifier="ADMIN@EXAMPLE.TEST",
        password="New!Admin42",
        confirmation="New!Admin42",
    )

    assert reset.id == administrator.id
    db_session.refresh(administrator)
    assert administrator.full_name == "Dedicated Administrator"
    assert administrator.username == "database_admin"
    assert administrator.email == "admin@example.test"
    assert administrator.role == "admin"
    assert administrator.is_active is True
    assert administrator.password_change_required is False
    assert administrator.version == 5
    assert administrator.password_hash != old_hash
    assert verify_password("New!Admin42", administrator.password_hash)
    assert not verify_password("Old!Password42", administrator.password_hash)
    db_session.refresh(operator_session)
    assert operator_session.revoked_at is not None
    event = db_session.scalar(select(AuditLog).where(AuditLog.event_type == "admin.password_reset"))
    assert event is not None
    assert event.metadata_json["source"] == "local_cli"
    assert "password" not in str(event.metadata_json).lower()
    assert administrator.id == reset.id
    assert session_token


@pytest.mark.parametrize(
    ("password", "confirmation", "error"),
    [
        ("weak", "weak", "between 6 and 20"),
        ("Ab1!x", "Ab1!x", "between 6 and 20"),
        ("Abcdefghij123456789!x", "Abcdefghij123456789!x", "between 6 and 20"),
        ("New!Admin42", "Different!Admin42", "confirmation does not match"),
    ],
)
def test_local_admin_password_reset_rejects_invalid_password_input(
    db_session: Session,
    password: str,
    confirmation: str,
    error: str,
) -> None:
    administrator = User(
        full_name="Dedicated Administrator",
        username="database_admin",
        email="admin@example.test",
        password_hash=hash_password("Old!Password42"),
        role="admin",
        is_active=True,
    )
    db_session.add(administrator)
    db_session.commit()
    old_hash = administrator.password_hash

    with pytest.raises(ValueError, match=error):
        reset_administrator_password(
            db_session,
            identifier="database_admin",
            password=password,
            confirmation=confirmation,
        )
    db_session.refresh(administrator)
    assert administrator.password_hash == old_hash
    assert db_session.scalar(select(AuditLog).where(AuditLog.event_type == "admin.password_reset")) is None


def test_local_admin_password_reset_rejects_unknown_account_without_mutation(db_session: Session) -> None:
    with pytest.raises(LookupError, match="No account matches"):
        reset_administrator_password(
            db_session,
            identifier="missing-admin",
            password="New!Administrator42",
            confirmation="New!Administrator42",
        )
    assert db_session.scalar(select(AuditLog).where(AuditLog.event_type == "admin.password_reset")) is None


def test_local_admin_password_reset_requires_exact_cli_confirmation(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("app.cli.get_session_factory", lambda: (_ for _ in ()).throw(AssertionError("database should not open")))
    monkeypatch.setattr("builtins.input", lambda _prompt: "RESET wrong-account")
    monkeypatch.setattr(sys, "argv", ["vuln", "reset-admin-password", "--identifier", "database_admin"])

    cli_main()

    assert "cancelled" in capsys.readouterr().out


def test_local_admin_password_reset_cli_updates_only_target_password(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    administrator = User(
        full_name="Dedicated Administrator",
        username="database_admin",
        email="admin@example.test",
        password_hash=hash_password("Old!Password42"),
        role="admin",
        is_active=True,
    )
    db_session.add(administrator)
    db_session.commit()
    administrator_id = administrator.id
    answers = iter(["RESET database_admin"])
    password_answers = iter(["New!Admin42", "New!Admin42"])
    monkeypatch.setattr("app.cli.get_session_factory", lambda: lambda: db_session)
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(password_answers))
    monkeypatch.setattr(sys, "argv", ["vuln", "reset-admin-password", "--identifier", "database_admin"])

    cli_main()

    stored = db_session.scalar(select(User).where(User.id == administrator_id))
    assert stored is not None
    assert stored.id == administrator_id
    assert stored.role == "admin"
    assert verify_password("New!Admin42", stored.password_hash)
    output = capsys.readouterr().out
    assert "New!Admin42" not in output
    assert "New!Admin42" not in caplog.text
    assert stored.password_hash not in caplog.text


def test_cli_rotation_requires_confirmation_and_leaves_state_unchanged(
    db_session: Session, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    old_key = provision_initial_api_key(db_session)
    _, stored_session, _ = create_operator_session(db_session, old_key)

    monkeypatch.setattr("app.cli.get_session_factory", lambda: (_ for _ in ()).throw(AssertionError("database should not open")))
    monkeypatch.setattr("builtins.input", lambda _prompt: "cancel")
    monkeypatch.setattr(sys, "argv", ["vuln", "rotate-api-key"])

    cli_main()

    output = capsys.readouterr().out
    assert "cancelled" in output
    assert old_key.encode() not in db_session.get(PlatformApiKey, 1).key_hash
    assert authenticate_api_key(db_session, old_key)
    db_session.refresh(stored_session)
    assert stored_session.revoked_at is None


def test_cli_rotation_prints_new_key_once_after_commit_and_revokes_sessions(
    db_session: Session,
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    old_key = provision_initial_api_key(db_session)
    _, stored_session, _ = create_operator_session(db_session, old_key)
    session_id = stored_session.id
    monkeypatch.setattr("app.cli.get_session_factory", lambda: lambda: db_session)
    monkeypatch.setattr("builtins.input", lambda _prompt: "ROTATE")
    monkeypatch.setattr(sys, "argv", ["vuln", "rotate-api-key"])

    cli_main()

    output = capsys.readouterr().out
    matches = re.findall(r"vsec_live_[A-Za-z0-9]{64}", output)
    assert len(matches) == 1
    new_key = matches[0]
    assert "cannot be retrieved later" in output
    assert old_key not in caplog.text
    assert new_key not in caplog.text
    assert not authenticate_api_key(db_session, old_key)
    assert authenticate_api_key(db_session, new_key)
    assert client.post("/api/v1/auth/session", headers={"X-API-Key": new_key}).status_code == 200
    stored_after_rotation = db_session.get(OperatorSession, session_id)
    assert stored_after_rotation is not None and stored_after_rotation.revoked_at is not None
    stored = db_session.get(PlatformApiKey, 1)
    assert stored is not None
    assert new_key.encode() not in stored.key_hash


def test_rotation_rolls_back_verifier_and_session_changes_on_commit_failure(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_key = provision_initial_api_key(db_session)
    _, stored_session, _ = create_operator_session(db_session, old_key)

    def fail_commit() -> None:
        raise RuntimeError("persistence failure")

    monkeypatch.setattr(db_session, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="persistence failure"):
        rotate_platform_api_key(db_session)

    assert authenticate_api_key(db_session, old_key)
    db_session.refresh(stored_session)
    assert stored_session.revoked_at is None


def test_cli_does_not_print_key_when_rotation_fails(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_key = provision_initial_api_key(db_session)
    create_operator_session(db_session, old_key)

    def fail_commit() -> None:
        raise RuntimeError("persistence failure")

    monkeypatch.setattr(db_session, "commit", fail_commit)
    monkeypatch.setattr("app.cli.get_session_factory", lambda: lambda: db_session)
    monkeypatch.setattr("builtins.input", lambda _prompt: "ROTATE")
    monkeypatch.setattr(sys, "argv", ["vuln", "rotate-api-key"])

    with pytest.raises(RuntimeError, match="persistence failure"):
        cli_main()

    assert "vsec_live_" not in capsys.readouterr().out


def test_protected_routes_reject_missing_malformed_and_invalid_keys(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    assert client.get("/api/v1/settings").status_code == 401
    assert client.get("/api/v1/settings", headers={"X-API-Key": "malformed"}).status_code == 401
    invalid_key = "vsec_live_" + "f" * 64
    assert client.get("/api/v1/settings", headers={"X-API-Key": invalid_key}).status_code == 401
    assert client.get("/api/v1/settings", headers={"X-API-Key": raw_key}).status_code == 200


def test_on_demand_scan_rejects_unauthenticated_request(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "192.168.29.31",
            "scan_type": "quick",
            "authorization_mode": "on_demand",
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 401


def test_api_key_exchange_creates_httponly_server_session(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    response = client.post("/api/v1/auth/session", headers={"X-API-Key": raw_key})
    assert response.status_code == 200
    cookie_header = response.headers["set-cookie"].lower()
    assert "httponly" in cookie_header
    assert "samesite=strict" in cookie_header
    assert raw_key not in response.text
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None
    assert raw_key not in stored_session.token_digest
    assert client.get("/api/v1/settings").status_code == 200


def test_session_login_authenticates_dashboard_and_sets_expected_cookie(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    login = client.post(
        "/api/v1/auth/session",
        headers={"X-API-Key": raw_key, "Origin": "http://localhost:5173"},
    )

    assert login.status_code == 200
    assert login.json()["authenticated"] is True
    assert login.json()["method"] == "session"

    cookie = SimpleCookie()
    cookie.load(login.headers["set-cookie"])
    morsel = cookie["vulnscanner_session"]
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    assert morsel["samesite"].lower() == "strict"
    assert morsel["secure"] == ""
    assert morsel["httponly"] is True
    assert morsel["max-age"] == "300"

    dashboard = client.get(
        "/api/v1/dashboard",
        headers={"Origin": "http://localhost:5173"},
    )
    assert dashboard.status_code == 200
    assert dashboard.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert dashboard.headers["access-control-allow-credentials"] == "true"


def test_cors_preflight_allows_exact_local_frontend_with_credentials(client: TestClient) -> None:
    response = client.options(
        "/api/v1/dashboard",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_session_inactivity_expiration_is_enforced(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    assert client.post("/api/v1/auth/session", headers={"X-API-Key": raw_key}).status_code == 200
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None
    stored_session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    response = client.get("/api/v1/settings")
    assert response.status_code == 401
    assert response.json()["detail"] == "Session expired"
    db_session.refresh(stored_session)
    assert stored_session.revoked_at is not None


def test_session_idle_policy_is_exactly_five_minutes_and_uses_last_activity(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    assert client.post("/api/v1/auth/session", headers={"X-API-Key": raw_key}).status_code == 200
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None
    created = stored_session.created_at
    expires = stored_session.expires_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    assert timedelta(seconds=299) <= expires - created <= timedelta(seconds=301)

    stored_session.last_activity_at = datetime.now(timezone.utc) - timedelta(minutes=5, seconds=1)
    # Keep expires_at in the future to prove the idle check uses the activity
    # timestamp rather than relying on the cookie/session expiry alone.
    stored_session.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    db_session.commit()
    response = client.get("/api/v1/settings")
    assert response.status_code == 401
    assert response.json()["detail"] == "Session expired"


def test_logout_is_idempotent_and_clears_server_session(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    assert client.post("/api/v1/auth/session", headers={"X-API-Key": raw_key}).status_code == 200
    response = client.delete("/api/v1/auth/session")
    assert response.status_code == 204
    assert "max-age=0" in response.headers["set-cookie"].lower()
    stored_session = db_session.scalar(select(OperatorSession))
    assert stored_session is not None and stored_session.revoked_at is not None
    assert client.delete("/api/v1/auth/session").status_code == 204


def test_regeneration_invalidates_previous_key_and_active_sessions(
    client: TestClient, db_session: Session
) -> None:
    old_key = provision_initial_api_key(db_session)
    assert client.post("/api/v1/auth/session", headers={"X-API-Key": old_key}).status_code == 200
    new_key = "vsec_live_" + "a1" * 32
    response = client.post(
        "/api/v1/settings/api-key/regenerate",
        headers={"X-API-Key": old_key},
        json={"api_key": new_key},
    )
    assert response.status_code == 200
    assert old_key not in response.text
    assert new_key not in response.text
    assert client.get("/api/v1/settings", headers={"X-API-Key": old_key}).status_code == 401
    assert client.get("/api/v1/settings", headers={"X-API-Key": new_key}).status_code == 200
    sessions = db_session.scalars(select(OperatorSession)).all()
    assert sessions and all(session.revoked_at is not None for session in sessions)


def test_revocation_endpoint_is_protected_and_revokes_key(
    client: TestClient, db_session: Session
) -> None:
    raw_key = provision_initial_api_key(db_session)
    assert client.delete("/api/v1/settings/api-key").status_code == 401
    assert client.delete("/api/v1/settings/api-key", headers={"X-API-Key": raw_key}).status_code == 204
    assert client.get("/api/v1/settings", headers={"X-API-Key": raw_key}).status_code == 401


def test_raw_credentials_are_absent_from_application_logs(
    client: TestClient, db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    raw_key = provision_initial_api_key(db_session)
    caplog.clear()
    response = client.get("/api/v1/settings", headers={"X-API-Key": raw_key})
    assert response.status_code == 200
    assert raw_key not in caplog.text
