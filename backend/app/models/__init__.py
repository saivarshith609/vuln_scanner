"""
VulnScanner API — Model registry.

Importing this module ensures all ORM models are loaded so that
``Base.metadata`` contains every table definition (required by Alembic).
"""

from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.authorized_target import AuthorizedTarget
from app.models.report import Report
from app.models.platform_setting import (
    IntegrationCredential,
    OperatorSession,
    PlatformApiKey,
    PlatformSetting,
)
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.vulnerability import Vulnerability
from app.models.user import User

__all__ = [
    "Asset", "AuditLog", "AuthorizedTarget", "IntegrationCredential", "OperatorSession", "PlatformApiKey",
    "PlatformSetting", "Report", "Scan", "ScanResult", "User", "Vulnerability",
]
