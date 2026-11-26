"""Schemas for bounded, authorized network discovery."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.scan import ScanAuthorizationMode


class DiscoveryTargetType(str, Enum):
    cidr = "cidr"
    range = "range"


class DiscoveryCreate(BaseModel):
    target_type: DiscoveryTargetType
    authorization_mode: ScanAuthorizationMode = ScanAuthorizationMode.allow_list
    cidr: str | None = Field(default=None, max_length=255)
    start_ip: str | None = Field(default=None, max_length=45)
    end_ip: str | None = Field(default=None, max_length=45)
    authorization_confirmed: bool = False

    @model_validator(mode="after")
    def require_mode_fields(self) -> "DiscoveryCreate":
        if self.target_type == DiscoveryTargetType.cidr and not self.cidr:
            raise ValueError("CIDR is required for subnet discovery.")
        if self.target_type == DiscoveryTargetType.range and (not self.start_ip or not self.end_ip):
            raise ValueError("Start and end IP addresses are required for range discovery.")
        return self


class DiscoveryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    target_kind: str
    range_start: str | None = None
    range_end: str | None = None
    authorization_mode: str = "allow_list"
    authorization_confirmed: bool = False
    authorization_confirmed_at: datetime | None = None
    status: str
    progress: int
    partial_results: bool
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class DiscoveredHostResponse(BaseModel):
    id: uuid.UUID
    discovery_id: uuid.UUID
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    discovery_status: str
    last_seen_at: datetime
    authorized: bool
