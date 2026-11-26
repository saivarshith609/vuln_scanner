"""
VulnScanner API — Common generic schemas (pagination, wrappers).
"""

from __future__ import annotations

import math
from typing import Generic, Sequence, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response envelope."""

    items: list[T] = Field(..., description="List of items for current page")
    total: int = Field(..., description="Total count across all pages")
    page: int = Field(..., description="Current page number (1-indexed)")
    size: int = Field(..., description="Page size limit")
    pages: int = Field(..., description="Total number of pages")

    @classmethod
    def create(
        cls,
        items: Sequence[T],
        total: int,
        page: int,
        size: int,
    ) -> PaginatedResponse[T]:
        """Factory helper calculating total pages."""
        pages = math.ceil(total / size) if size > 0 and total > 0 else (1 if total == 0 else 0)
        return cls(
            items=list(items),
            total=total,
            page=page,
            size=size,
            pages=max(pages, 1),
        )
