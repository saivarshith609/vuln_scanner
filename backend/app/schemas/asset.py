"""
VulnScanner API — Asset Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AssetType(str, Enum):
    server = "server"
    workstation = "workstation"
    network = "network"
    web = "web"
    api = "api"
    cloud = "cloud"
    iot = "iot"
    other = "other"


class AssetCreate(BaseModel):
    """Request body for creating an asset."""
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    target: str = Field(..., min_length=1, max_length=255)
    description: str | None = None


class AssetUpdate(BaseModel):
    """Request body for updating an asset — all fields optional."""
    name: str | None = Field(None, min_length=1, max_length=255)
    asset_type: AssetType | None = None
    target: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None


class AssetResponse(BaseModel):
    """API response for a single asset."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    asset_type: str
    target: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime
