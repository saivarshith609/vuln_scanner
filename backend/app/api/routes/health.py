"""
VulnScanner API — Health check routes.
"""

import logging

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


class HealthResponse(BaseModel):
    """Structured health-check response."""
    status: str
    application: str
    version: str


class DatabaseHealthResponse(BaseModel):
    """Structured database health-check response."""
    status: str
    database: str


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Application health check",
    description="Returns the current health status of the VulnScanner API.",
)
def health_check() -> HealthResponse:
    """Return the application health status."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        application=settings.APP_NAME,
        version=settings.APP_VERSION,
    )


@router.get(
    "/health/database",
    response_model=DatabaseHealthResponse,
    responses={
        200: {"description": "Database is reachable"},
        503: {"description": "Database is unavailable"},
    },
    summary="Database connectivity check",
    description="Verifies that PostgreSQL is reachable.",
)
def database_health_check(db: Session = Depends(get_db)) -> JSONResponse:
    """Check database connectivity with a lightweight query."""
    try:
        db.execute(text("SELECT 1"))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "healthy", "database": "reachable"},
        )
    except Exception:
        logger.exception("Database health check failed")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "database": "unreachable"},
        )
