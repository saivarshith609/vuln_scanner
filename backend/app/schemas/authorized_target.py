"""
VulnScanner API — AuthorizedTarget Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scanner.auth_service import normalize_target


class AuthorizedTargetCreate(BaseModel):
    """Request body for creating an authorized target entry."""

    target: str = Field(..., min_length=1, max_length=255, description="IP, CIDR, or hostname")
    description: str | None = Field(None, max_length=1000)
    is_enabled: bool = True

    @field_validator("target")
    @classmethod
    def target_must_be_valid(cls, v: str) -> str:
        return normalize_target(v)


class AuthorizedTargetUpdate(BaseModel):
    """Request body for patching an authorized target entry."""

    description: str | None = Field(None, max_length=1000)
    is_enabled: bool | None = None


class AuthorizedTargetResponse(BaseModel):
    """API response for a single authorized target entry."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    description: str | None = None
    is_enabled: bool
    created_at: datetime
