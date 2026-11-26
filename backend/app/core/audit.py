"""Safe append-only audit helpers.

Callers control the surrounding transaction.  Metadata is allow-listed by the
caller and must never contain credentials, password material, or session data.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def add_audit_event(
    db: Session,
    event_type: str,
    *,
    actor_user_id: uuid.UUID | None = None,
    outcome: str = "success",
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    ip_address: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    event = AuditLog(
        actor_user_id=actor_user_id,
        event_type=event_type,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=ip_address,
        metadata_json=metadata or {},
    )
    db.add(event)
    return event
