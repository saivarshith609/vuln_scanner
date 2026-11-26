"""
VulnScanner API — Authorized target management endpoints.

These endpoints allow operators to manage the explicit allow-list that
gates every scan.  They are mounted under the local API prefix and
should only be accessible from localhost (enforced by the server bind
address ``127.0.0.1``).

CRUD operations:
  GET    /api/v1/authorized-targets        — list all entries
  POST   /api/v1/authorized-targets        — add an entry
  GET    /api/v1/authorized-targets/{id}   — get one entry
  PATCH  /api/v1/authorized-targets/{id}   — enable/disable or update notes
  DELETE /api/v1/authorized-targets/{id}   — remove an entry
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.models.authorized_target import AuthorizedTarget
from app.schemas.authorized_target import (
    AuthorizedTargetCreate,
    AuthorizedTargetResponse,
    AuthorizedTargetUpdate,
)
from app.schemas.common import PaginatedResponse

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[AuthorizedTargetResponse],
    summary="List authorized targets",
    description="Return a paginated list of all authorized scan target entries.",
)
def list_authorized_targets(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    enabled_only: bool = Query(False, description="When true, only return enabled entries."),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[AuthorizedTargetResponse]:
    query = select(AuthorizedTarget)
    if not operator.is_admin:
        query = query.where(AuthorizedTarget.owner_user_id == operator.user_id)
    if enabled_only:
        query = query.where(AuthorizedTarget.is_enabled.is_(True))

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    offset = (page - 1) * size
    items = db.scalars(
        query.order_by(AuthorizedTarget.created_at.desc()).offset(offset).limit(size)
    ).all()

    return PaginatedResponse.create(
        items=[AuthorizedTargetResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
    )


@router.post(
    "",
    response_model=AuthorizedTargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add authorized target",
    description="Register a new authorized scan target. Input is validated for syntactic correctness.",
)
def create_authorized_target(
    target_in: AuthorizedTargetCreate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AuthorizedTargetResponse:
    duplicate = db.scalar(
        select(AuthorizedTarget).where(
            AuthorizedTarget.owner_user_id == operator.user_id,
            AuthorizedTarget.target == target_in.target,
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target {target_in.target!r} already exists in the authorized list.",
        )
    entry = AuthorizedTarget(
        id=uuid.uuid4(),
        owner_user_id=operator.user_id,
        target=target_in.target,
        description=target_in.description,
        is_enabled=target_in.is_enabled,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Target {target_in.target!r} already exists in the authorized list.",
        )
    db.refresh(entry)
    return AuthorizedTargetResponse.model_validate(entry)


@router.get(
    "/{target_id}",
    response_model=AuthorizedTargetResponse,
    summary="Get authorized target",
)
def get_authorized_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AuthorizedTargetResponse:
    entry = db.get(AuthorizedTarget, target_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Authorized target '{target_id}' not found.",
        )
    require_owner(operator, entry.owner_user_id)
    return AuthorizedTargetResponse.model_validate(entry)


@router.patch(
    "/{target_id}",
    response_model=AuthorizedTargetResponse,
    summary="Update authorized target",
    description="Enable/disable a target entry or update its description.",
)
def update_authorized_target(
    target_id: uuid.UUID,
    update_in: AuthorizedTargetUpdate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AuthorizedTargetResponse:
    entry = db.get(AuthorizedTarget, target_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Authorized target '{target_id}' not found.",
        )
    require_owner(operator, entry.owner_user_id)

    update_data = update_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(entry, field, value)

    db.commit()
    db.refresh(entry)
    return AuthorizedTargetResponse.model_validate(entry)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete authorized target",
    description="Permanently remove a target from the authorized list.",
)
def delete_authorized_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> Response:
    entry = db.get(AuthorizedTarget, target_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Authorized target '{target_id}' not found.",
        )
    require_owner(operator, entry.owner_user_id)
    db.delete(entry)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
