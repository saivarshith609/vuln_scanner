"""
VulnScanner API — ScanResult Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanResultResponse(BaseModel):
    """API response for a single scan result (host/port/service discovery)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    host_address: str
    host_state: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    port: int | None = None
    protocol: str | None = None
    port_state: str | None = None
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    service_extra_info: str | None = None
    created_at: datetime
