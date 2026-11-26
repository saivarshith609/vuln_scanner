"""Phase 10 platform settings and secret-management tests."""

import asyncio
from collections.abc import Generator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.auth import AuthenticatedOperator, require_authentication
from app.core.secrets import decrypt_secret, verify_api_key
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.platform_setting import IntegrationCredential, PlatformApiKey, PlatformSetting
from app.scanner.nmap_service import NmapScannerService, scanner_service


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("INTEGRATION_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    get_settings.cache_clear()
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_get_settings_creates_safe_persisted_defaults(client: TestClient, db_session: Session) -> None:
    response = client.get("/api/v1/settings")
    assert response.status_code == 200
    data = response.json()
    assert data["preferences"]["max_concurrent_scans"] >= 1
    assert data["integrations"]["jira"] == {
        "configured": False,
        "masked_hint": None,
        "updated_at": None,
    }
    assert data["api_key"]["configured"] is False
    assert "DATABASE_URL" not in str(data)
    assert db_session.get(PlatformSetting, 1) is not None


def test_update_settings_validates_and_persists(client: TestClient, db_session: Session) -> None:
    payload = {
        "max_concurrent_scans": 8,
        "scanner_rate_limit_per_minute": 240,
        "session_timeout_minutes": 60,
        "accent_color": "#10b981",
    }
    response = client.patch("/api/v1/settings", json=payload)
    assert response.status_code == 200
    assert response.json()["preferences"] == payload
    assert response.json()["runtime"]["runtime_max_concurrent_scans"] == 8
    assert response.json()["runtime"]["runtime_rate_limit_per_minute"] == 240
    assert response.json()["runtime"]["rate_limit_enforced"] is True
    assert scanner_service.runtime_max_concurrent == 8
    assert scanner_service.runtime_rate_limit_per_minute == 240
    db_session.expire_all()
    assert db_session.get(PlatformSetting, 1).accent_color == "#10b981"

    invalid = client.patch("/api/v1/settings", json={**payload, "max_concurrent_scans": 0})
    assert invalid.status_code == 422


def test_integration_secret_is_encrypted_replaced_and_never_returned(
    client: TestClient, db_session: Session
) -> None:
    first_secret = "jira-secret-token-123456"
    response = client.put("/api/v1/settings/integrations/jira", json={"secret": first_secret})
    assert response.status_code == 200
    assert first_secret not in response.text
    assert response.json()["configured"] is True

    stored = db_session.scalar(select(IntegrationCredential).where(IntegrationCredential.provider == "jira"))
    assert stored is not None
    assert first_secret.encode() not in stored.encrypted_secret
    assert decrypt_secret(stored.encrypted_secret) == first_secret

    replacement = "jira-replacement-token-987654"
    replaced = client.put("/api/v1/settings/integrations/jira", json={"secret": replacement})
    assert replaced.status_code == 200
    assert replacement not in replaced.text
    db_session.refresh(stored)
    assert decrypt_secret(stored.encrypted_secret) == replacement


def test_slack_validation_and_integration_deletion(client: TestClient) -> None:
    invalid = client.put("/api/v1/settings/integrations/slack", json={"secret": "not-a-webhook"})
    assert invalid.status_code == 422

    missing = client.delete("/api/v1/settings/integrations/splunk")
    assert missing.status_code == 404

    valid_secret = "https://hooks.slack.com/services/T000/B000/secret-value"
    assert client.put("/api/v1/settings/integrations/slack", json={"secret": valid_secret}).status_code == 200
    assert client.delete("/api/v1/settings/integrations/slack").status_code == 204
    assert client.get("/api/v1/settings").json()["integrations"]["slack"]["configured"] is False


def test_api_key_is_hashed_replaced_and_deleted(client: TestClient, db_session: Session) -> None:
    raw_key = "vsec_live_" + "A1" * 32
    response = client.post("/api/v1/settings/api-key/regenerate", json={"api_key": raw_key})
    assert response.status_code == 200
    assert raw_key not in response.text

    stored = db_session.get(PlatformApiKey, 1)
    assert stored is not None
    assert raw_key.encode() not in stored.key_hash
    assert verify_api_key(raw_key, stored.key_hash, stored.hash_salt)

    assert client.delete("/api/v1/settings/api-key").status_code == 204
    assert client.delete("/api/v1/settings/api-key").status_code == 404


def test_secret_save_requires_server_encryption_configuration(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INTEGRATION_ENCRYPTION_KEY", "")
    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        response = test_client.put(
            "/api/v1/settings/integrations/jira",
            json={"secret": "valid-secret-value"},
        )
    assert response.status_code == 503
    assert "valid-secret-value" not in response.text
    assert db_session.scalar(select(IntegrationCredential)) is None
    get_settings.cache_clear()


def test_invalid_encryption_key_fails_without_storing_secret(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INTEGRATION_ENCRYPTION_KEY", "invalid-fernet-key")
    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[require_authentication] = lambda: AuthenticatedOperator(method="test")
    with TestClient(app) as test_client:
        response = test_client.put(
            "/api/v1/settings/integrations/jira",
            json={"secret": "another-valid-secret"},
        )
    assert response.status_code == 503
    assert "another-valid-secret" not in response.text
    assert db_session.scalar(select(IntegrationCredential)) is None
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_scanner_dispatch_limiter_enforces_saved_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = NmapScannerService()
    assert service.configure_limits(2, 1)
    assert service.runtime_max_concurrent == 2
    assert service.runtime_rate_limit_per_minute == 1
    assert service._semaphore is not None
    assert service._semaphore._value == 2

    loop = asyncio.get_running_loop()
    service._dispatch_times.append(loop.time())
    sleep_delays: list[float] = []

    async def release_rate_slot(delay: float) -> None:
        sleep_delays.append(delay)
        service._dispatch_times.clear()

    monkeypatch.setattr("app.scanner.nmap_service.asyncio.sleep", release_rate_slot)
    await service._wait_for_rate_slot()
    assert sleep_delays and sleep_delays[0] > 0
    assert len(service._dispatch_times) == 1
