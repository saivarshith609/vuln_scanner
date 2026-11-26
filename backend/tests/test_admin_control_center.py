"""Isolated authorization and account-lifecycle tests for the admin control center."""

import uuid
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.passwords import hash_password, verify_password
from app.core.auth import require_admin
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.user import User

PASSWORD = "Secure!Admin123"


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def make_user(db: Session, username: str, role: str = "user", active: bool = True) -> User:
    user = User(
        id=uuid.uuid4(), full_name=f"{username.title()} User", username=username,
        email=f"{username}@example.test", password_hash=hash_password(PASSWORD),
        role=role, is_active=active,
    )
    db.add(user)
    db.commit()
    return user


def login(client: TestClient, username: str, *, administrator: bool = False) -> dict[str, str]:
    endpoint = "/api/v1/auth/admin/login" if administrator else "/api/v1/auth/login"
    response = client.post(endpoint, json={"identifier": username, "password": PASSWORD})
    assert response.status_code == 200
    return {"X-CSRF-Token": client.cookies.get("vulnscanner_csrf") or ""}


def test_normal_user_cannot_access_admin_api(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "ordinary")
    login(client, "ordinary")
    assert client.get("/api/v1/admin/overview").status_code == 403


def test_unauthenticated_admin_request_is_unauthorized(client: TestClient) -> None:
    assert client.get("/api/v1/admin/overview").status_code == 401


def test_every_admin_route_has_the_server_side_admin_dependency() -> None:
    app = create_app()
    admin_routes = [
        route for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/admin/")
    ]
    assert admin_routes
    for route in admin_routes:
        assert any(dependency.call is require_admin for dependency in route.dependant.dependencies), route.path


def test_normal_user_cannot_promote_self_with_modified_request(
    client: TestClient, db_session: Session,
) -> None:
    user = make_user(db_session, "ordinary")
    headers = login(client, "ordinary")

    response = client.patch(
        f"/api/v1/admin/users/{user.id}",
        headers=headers,
        json={"version": user.version, "role": "admin"},
    )

    assert response.status_code == 403
    db_session.refresh(user)
    assert user.role == "user"


def test_admin_overview_and_user_search_use_persisted_data(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    target = make_user(db_session, "analyst")
    login(client, "rootadmin", administrator=True)
    overview = client.get("/api/v1/admin/overview")
    assert overview.status_code == 200
    assert overview.json()["total_users"] == 2
    users = client.get("/api/v1/admin/users?search=analyst")
    assert users.status_code == 200
    assert users.json()["items"][0]["id"] == str(target.id)
    assert "password_hash" not in users.text


def test_admin_edit_uses_versioning_and_rejects_duplicates(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    target = make_user(db_session, "analyst")
    make_user(db_session, "existing")
    headers = login(client, "rootadmin", administrator=True)
    response = client.patch(f"/api/v1/admin/users/{target.id}", headers=headers, json={
        "version": target.version, "full_name": "Updated Analyst", "email": "updated@example.test",
    })
    assert response.status_code == 200
    assert response.json()["version"] == 2
    stale = client.patch(f"/api/v1/admin/users/{target.id}", headers=headers, json={"version": 1, "full_name": "Stale"})
    assert stale.status_code == 409
    duplicate = client.patch(f"/api/v1/admin/users/{target.id}", headers=headers, json={"version": 2, "username": "existing"})
    assert duplicate.status_code == 409


def test_last_active_admin_is_protected(client: TestClient, db_session: Session) -> None:
    admin = make_user(db_session, "rootadmin", "admin")
    headers = login(client, "rootadmin", administrator=True)
    response = client.post(f"/api/v1/admin/users/{admin.id}/disable", headers=headers)
    assert response.status_code == 409
    db_session.refresh(admin)
    assert admin.is_active is True


def test_disable_enable_and_session_revocation(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    target = make_user(db_session, "analyst")
    login(client, "analyst")
    client.cookies.clear()
    headers = login(client, "rootadmin", administrator=True)
    disabled = client.post(f"/api/v1/admin/users/{target.id}/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False
    assert disabled.json()["active_sessions"] == 0
    enabled = client.post(f"/api/v1/admin/users/{target.id}/enable", headers=headers)
    assert enabled.status_code == 200
    assert enabled.json()["is_active"] is True


def test_password_reset_hashes_secret_forces_change_and_audits(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    target = make_user(db_session, "analyst")
    headers = login(client, "rootadmin", administrator=True)
    temporary = "Temporary!Secret456"
    response = client.post(f"/api/v1/admin/users/{target.id}/reset-password", headers=headers, json={
        "temporary_password": temporary, "confirm_password": temporary,
    })
    assert response.status_code == 200
    db_session.refresh(target)
    assert target.password_change_required is True
    assert verify_password(temporary, target.password_hash)
    assert temporary not in response.text
    event = db_session.scalar(select(AuditLog).where(AuditLog.event_type == "admin.password_reset"))
    assert event is not None
    assert temporary not in str(event.metadata_json)


def test_user_scan_history_is_scoped_to_selected_user(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    first = make_user(db_session, "first")
    second = make_user(db_session, "second")
    db_session.add_all([
        Scan(owner_user_id=first.id, target="first.example", operation="scan", scan_type="quick", status="completed", progress=100, created_at=datetime.now(timezone.utc)),
        Scan(owner_user_id=second.id, target="second.example", operation="scan", scan_type="quick", status="completed", progress=100, created_at=datetime.now(timezone.utc)),
    ])
    db_session.commit()
    login(client, "rootadmin", administrator=True)
    response = client.get(f"/api/v1/admin/users/{first.id}/scans")
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["target"] == "first.example"


def test_audit_log_is_admin_only_and_contains_account_changes(client: TestClient, db_session: Session) -> None:
    make_user(db_session, "rootadmin", "admin")
    target = make_user(db_session, "analyst")
    headers = login(client, "rootadmin", administrator=True)
    changed = client.patch(f"/api/v1/admin/users/{target.id}", headers=headers, json={"version": 1, "full_name": "Audit Target"})
    assert changed.status_code == 200
    audit = client.get("/api/v1/admin/audit-logs?event_type=admin.user_updated")
    assert audit.status_code == 200
    assert audit.json()["total"] == 1
    assert audit.json()["items"][0]["resource_id"] == str(target.id)
