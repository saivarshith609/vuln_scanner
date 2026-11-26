"""
VulnScanner API — Scan Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ScanType(str, Enum):
    full = "full"
    quick = "quick"
    network = "network"
    web = "web"
    api = "api"
    compliance = "compliance"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanAuthorizationMode(str, Enum):
    allow_list = "allow_list"
    on_demand = "on_demand"


Progress = Annotated[int, Field(ge=0, le=100)]


class ScanCreate(BaseModel):
    """Request body for creating a scan."""
    asset_id: uuid.UUID | None = None
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType
    authorization_mode: ScanAuthorizationMode = ScanAuthorizationMode.allow_list
    authorization_confirmed: bool = False


class ScanUpdate(BaseModel):
    """Request body for updating scan status / progress."""
    status: ScanStatus | None = None
    progress: Progress | None = None


class ScanResponse(BaseModel):
    """API response for a single scan."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID | None = None
    target: str
    operation: str = "scan"
    target_kind: str = "host"
    range_start: str | None = None
    range_end: str | None = None
    authorization_mode: str = "allow_list"
    authorization_confirmed: bool = False
    authorization_confirmed_at: datetime | None = None
    partial_results: bool = False
    scan_type: str
    status: str
    progress: int
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
