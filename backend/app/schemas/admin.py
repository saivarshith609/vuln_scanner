"""Administrator control-center request and response schemas."""

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.auth import EMAIL_RE, normalize_email, validate_password_policy, validate_username_policy


class AdminUserUpdate(BaseModel):
    version: int = Field(ge=1)
    full_name: str | None = Field(default=None, min_length=2, max_length=255)
    username: str | None = Field(default=None, min_length=6, max_length=64)
    email: str | None = Field(default=None, min_length=5, max_length=320)
    role: Literal["user", "admin"] | None = None
    is_active: bool | None = None

    @field_validator("full_name")
    @classmethod
    def clean_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.strip().split())
        if len(cleaned) < 2:
            raise ValueError("Full name is required.")
        return cleaned

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_username_policy(value)

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_email(value)
        if not EMAIL_RE.fullmatch(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class AdminPasswordResetRequest(BaseModel):
    temporary_password: str
    confirm_password: str

    @field_validator("temporary_password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def passwords_match(self) -> "AdminPasswordResetRequest":
        if self.temporary_password != self.confirm_password:
            raise ValueError("Password confirmation does not match.")
        return self


class AdminActionResponse(BaseModel):
    success: bool = True
    message: str


class AdminSessionSummary(BaseModel):
    reference: str
    login_time: datetime
    last_activity: datetime
    expires_at: datetime


class AdminUserSummary(BaseModel):
    id: uuid.UUID
    full_name: str
    username: str
    email: str
    role: str
    is_active: bool
    password_change_required: bool
    version: int
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None
    last_activity_at: datetime | None
    online: bool
    active_sessions: int
    total_scans: int = 0
    total_findings: int = 0
    total_reports: int = 0


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    created_at: datetime
    actor_user_id: uuid.UUID | None
    actor_username: str | None
    event_type: str
    outcome: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    metadata: dict[str, Any]


class LoginActivityResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    username: str | None
    attempted_identifier: str | None
    browser_name: str
    browser_version: str | None
    operating_system: str
    os_version: str | None
    device_type: str
    login_status: str
    attempted_at: datetime


class AdminUserDetail(AdminUserSummary):
    sessions: list[AdminSessionSummary]
    recent_events: list[AuditLogResponse]


class AdminScanSummary(BaseModel):
    id: uuid.UUID
    owner_user_id: uuid.UUID | None
    owner_username: str | None
    target: str
    operation: str
    authorization_mode: str
    scan_type: str
    status: str
    progress: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: int | None
    findings_count: int
    error_message: str | None


class AdminReportSummary(BaseModel):
    id: uuid.UUID
    owner_user_id: uuid.UUID | None
    owner_username: str | None
    scan_id: uuid.UUID | None
    report_code: str | None
    name: str
    target: str
    report_type: str
    format: str
    status: str
    total_findings: int
    created_at: datetime


class AdminVulnerabilitySummary(BaseModel):
    id: uuid.UUID
    title: str
    cve_id: str | None
    severity: str
    cvss_score: float | None
    target: str
    port: int | None
    scan_id: uuid.UUID
    owner_user_id: uuid.UUID | None
    owner_username: str | None
    status: str
    created_at: datetime
    remediation: str | None


class AdminDiscoverySummary(BaseModel):
    id: uuid.UUID
    owner_user_id: uuid.UUID | None
    owner_username: str | None
    target: str
    target_kind: str
    authorization_mode: str
    status: str
    hosts_discovered: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None


class AdminHealth(BaseModel):
    backend: Literal["healthy", "unavailable"]
    database: Literal["healthy", "unavailable"]
    nmap: Literal["healthy", "unavailable"]


class AdminOverview(BaseModel):
    total_users: int
    active_users: int
    disabled_users: int
    online_users: int
    total_scans: int
    running_scans: int
    completed_scans: int
    failed_scans: int
    cancelled_scans: int
    total_findings: int
    findings_by_severity: dict[str, int]
    recent_discoveries: list[AdminDiscoverySummary]
    recent_activity: list[AuditLogResponse]
    health: AdminHealth


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        return validate_password_policy(value)

    @model_validator(mode="after")
    def passwords_match(self) -> "ChangePasswordRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("Password confirmation does not match.")
        if self.current_password == self.new_password:
            raise ValueError("The new password must be different from the current password.")
        return self
