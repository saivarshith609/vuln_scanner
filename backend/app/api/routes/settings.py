"""Platform settings and write-only secret-management endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.auth import clear_session_cookie, revoke_all_sessions
from app.core.secrets import (
    SecretConfigurationError,
    encrypt_secret,
    encryption_is_configured,
    hash_api_key,
    masked_hint,
)
from app.db.session import get_db
from app.models.platform_setting import IntegrationCredential, PlatformApiKey, PlatformSetting
from app.scanner.nmap_service import scanner_service
from app.schemas.settings import (
    ApiKeyReplace,
    IntegrationProvider,
    IntegrationSecretWrite,
    PlatformPreferences,
    PlatformSettingsResponse,
    PlatformSettingsUpdate,
    RuntimeStatus,
    SecretStatus,
)

router = APIRouter()
PROVIDERS: tuple[IntegrationProvider, ...] = ("jira", "slack", "splunk")


def _preferences(db: Session) -> PlatformSetting:
    stored = db.get(PlatformSetting, 1)
    if stored is None:
        runtime = get_settings()
        stored = PlatformSetting(id=1, max_concurrent_scans=runtime.NMAP_MAX_CONCURRENT)
        db.add(stored)
        db.commit()
        db.refresh(stored)
    return stored


def _secret_status(record: IntegrationCredential | PlatformApiKey | None) -> SecretStatus:
    return SecretStatus(
        configured=record is not None,
        masked_hint=record.masked_hint if record else None,
        updated_at=record.updated_at if record else None,
    )


def _response(db: Session) -> PlatformSettingsResponse:
    stored = _preferences(db)
    credentials = {
        item.provider: item
        for item in db.scalars(select(IntegrationCredential)).all()
    }
    api_key = db.get(PlatformApiKey, 1)
    runtime = get_settings()
    scanner_service.configure_limits(
        stored.max_concurrent_scans,
        stored.scanner_rate_limit_per_minute,
    )
    return PlatformSettingsResponse(
        preferences=PlatformPreferences(
            max_concurrent_scans=stored.max_concurrent_scans,
            scanner_rate_limit_per_minute=stored.scanner_rate_limit_per_minute,
            session_timeout_minutes=stored.session_timeout_minutes,
            accent_color=stored.accent_color,
        ),
        integrations={provider: _secret_status(credentials.get(provider)) for provider in PROVIDERS},
        api_key=_secret_status(api_key),
        runtime=RuntimeStatus(
            environment=runtime.APP_ENV,
            app_version=runtime.APP_VERSION,
            nmap_available=scanner_service.nmap_available,
            runtime_max_concurrent_scans=scanner_service.runtime_max_concurrent,
            runtime_rate_limit_per_minute=scanner_service.runtime_rate_limit_per_minute,
            concurrency_restart_required=(
                stored.max_concurrent_scans != scanner_service.runtime_max_concurrent
            ),
            integration_encryption_configured=encryption_is_configured(),
        ),
    )


@router.get("", response_model=PlatformSettingsResponse)
def get_platform_settings(db: Session = Depends(get_db)) -> PlatformSettingsResponse:
    return _response(db)


@router.patch("", response_model=PlatformSettingsResponse)
def update_platform_settings(
    payload: PlatformSettingsUpdate, db: Session = Depends(get_db)
) -> PlatformSettingsResponse:
    stored = _preferences(db)
    for field, value in payload.model_dump().items():
        setattr(stored, field, value)
    db.commit()
    db.refresh(stored)
    return _response(db)


@router.put("/integrations/{provider}", response_model=SecretStatus)
def replace_integration_secret(
    provider: IntegrationProvider,
    payload: IntegrationSecretWrite,
    db: Session = Depends(get_db),
) -> SecretStatus:
    raw_secret = payload.secret.get_secret_value().strip()
    if provider == "slack" and not raw_secret.startswith("https://hooks.slack.com/services/"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Slack credential must be an HTTPS incoming-webhook URL",
        )
    try:
        encrypted = encrypt_secret(raw_secret)
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from None

    record = db.get(IntegrationCredential, provider)
    if record is None:
        record = IntegrationCredential(provider=provider, encrypted_secret=encrypted, masked_hint=masked_hint(raw_secret))
        db.add(record)
    else:
        record.encrypted_secret = encrypted
        record.masked_hint = masked_hint(raw_secret)
        record.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(record)
    return _secret_status(record)


@router.delete("/integrations/{provider}", status_code=status.HTTP_204_NO_CONTENT)
def remove_integration_secret(provider: IntegrationProvider, db: Session = Depends(get_db)) -> Response:
    record = db.get(IntegrationCredential, provider)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration credential is not configured")
    db.delete(record)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/api-key/regenerate", response_model=SecretStatus)
def replace_platform_api_key(
    payload: ApiKeyReplace,
    response: Response,
    db: Session = Depends(get_db),
) -> SecretStatus:
    raw_key = payload.api_key.get_secret_value()
    key_hash, salt = hash_api_key(raw_key)
    record = db.get(PlatformApiKey, 1)
    if record is None:
        record = PlatformApiKey(id=1, key_hash=key_hash, hash_salt=salt, masked_hint=masked_hint(raw_key))
        db.add(record)
    else:
        record.key_hash = key_hash
        record.hash_salt = salt
        record.masked_hint = masked_hint(raw_key)
        record.updated_at = datetime.now(timezone.utc)
    revoke_all_sessions(db)
    db.commit()
    db.refresh(record)
    clear_session_cookie(response)
    return _secret_status(record)


@router.delete("/api-key", status_code=status.HTTP_204_NO_CONTENT)
def remove_platform_api_key(response: Response, db: Session = Depends(get_db)) -> Response:
    record = db.get(PlatformApiKey, 1)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform API key is not configured")
    revoke_all_sessions(db)
    db.delete(record)
    db.commit()
    clear_session_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
