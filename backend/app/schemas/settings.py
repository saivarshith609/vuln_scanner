"""Validated request and safe response schemas for Phase 10 settings."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator

IntegrationProvider = Literal["jira", "slack", "splunk"]


class PlatformPreferences(BaseModel):
    max_concurrent_scans: int = Field(ge=1, le=32)
    scanner_rate_limit_per_minute: int = Field(ge=1, le=10000)
    session_timeout_minutes: int = Field(ge=5, le=1440)
    accent_color: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")


class PlatformSettingsUpdate(PlatformPreferences):
    pass


class IntegrationSecretWrite(BaseModel):
    secret: SecretStr = Field(min_length=8, max_length=4096)

    @field_validator("secret")
    @classmethod
    def reject_blank_secret(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("Secret must not be blank")
        return value


class ApiKeyReplace(BaseModel):
    api_key: SecretStr = Field(min_length=40, max_length=200)

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.startswith("vsec_live_") or not raw[10:].isalnum():
            raise ValueError("API key must use the vsec_live_ prefix and contain only letters and digits")
        return value


class SecretStatus(BaseModel):
    configured: bool
    masked_hint: str | None = None
    updated_at: datetime | None = None


class RuntimeStatus(BaseModel):
    environment: str
    app_version: str
    nmap_available: bool
    runtime_max_concurrent_scans: int
    runtime_rate_limit_per_minute: int
    concurrency_restart_required: bool
    rate_limit_enforced: bool = True
    session_enforcement_available: bool = True
    api_key_authentication_available: bool = True
    integration_encryption_configured: bool


class PlatformSettingsResponse(BaseModel):
    preferences: PlatformPreferences
    integrations: dict[IntegrationProvider, SecretStatus]
    api_key: SecretStatus
    runtime: RuntimeStatus
