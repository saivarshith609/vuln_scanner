"""
VulnScanner API — Asset management endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.auth import AuthenticatedOperator, require_authentication, require_owner
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from app.schemas.common import PaginatedResponse

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[AssetResponse],
    summary="List assets",
    description="Retrieve a paginated list of assets with optional search and type filtering.",
)
def list_assets(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, description="Search term for name or target"),
    asset_type: str | None = Query(None, description="Filter by asset type"),
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> PaginatedResponse[AssetResponse]:
    query = select(Asset)
    if not operator.is_admin:
        query = query.where(Asset.owner_user_id == operator.user_id)

    if search:
        search_term = f"%{search.strip()}%"
        query = query.where(
            or_(
                Asset.name.ilike(search_term),
                Asset.target.ilike(search_term),
            )
        )

    if asset_type:
        query = query.where(Asset.asset_type == asset_type.strip().lower())

    # Calculate total count
    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.scalar(count_stmt) or 0

    # Paginate and order by newest first
    offset = (page - 1) * size
    stmt = query.order_by(Asset.created_at.desc()).offset(offset).limit(size)
    items = db.scalars(stmt).all()

    validated_items = [AssetResponse.model_validate(item) for item in items]
    return PaginatedResponse.create(
        items=validated_items,
        total=total,
        page=page,
        size=size,
    )


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create asset",
    description="Register a new network asset. Does not initiate any scanning or network discovery.",
)
def create_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AssetResponse:
    now = datetime.now(timezone.utc)
    asset = Asset(
        id=uuid.uuid4(),
        owner_user_id=operator.user_id,
        name=asset_in.name.strip(),
        asset_type=asset_in.asset_type.value,
        target=asset_in.target.strip(),
        description=asset_in.description.strip() if asset_in.description else None,
        created_at=now,
        updated_at=now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Get asset by ID",
    description="Retrieve details of a single asset by UUID.",
)
def get_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AssetResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID '{asset_id}' not found",
        )
    require_owner(operator, asset.owner_user_id)
    return AssetResponse.model_validate(asset)


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Update asset",
    description="Partially update an asset's attributes.",
)
def update_asset(
    asset_id: uuid.UUID,
    asset_in: AssetUpdate,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> AssetResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID '{asset_id}' not found",
        )
    require_owner(operator, asset.owner_user_id)

    update_data = asset_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "asset_type" and value is not None:
            setattr(asset, field, value.value if hasattr(value, "value") else str(value))
        elif value is not None and isinstance(value, str):
            setattr(asset, field, value.strip())
        else:
            setattr(asset, field, value)

    asset.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete asset",
    description="Safely delete an asset. Any linked scans or vulnerabilities will retain audit integrity with asset_id set to null.",
)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    operator: AuthenticatedOperator = Depends(require_authentication),
) -> Response:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID '{asset_id}' not found",
        )
    require_owner(operator, asset.owner_user_id)

    db.delete(asset)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
