"""
VulnScanner API — FastAPI application factory (Phase 4.2).

Changes from Phase 3:
- Adds lifespan context manager that initializes and shuts down the
  NmapScannerService cleanly.
- Registers /api/v1/authorized-targets and /api/v1/scan-results routes.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.auth import require_admin, require_authentication
from app.api.routes.auth import router as auth_router
from app.api.routes.admin import router as admin_router
from app.api.routes.assets import router as assets_router
from app.api.routes.authorized_targets import router as authorized_targets_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.discoveries import router as discoveries_router
from app.api.routes.health import router as health_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scan_results import router as scan_results_router
from app.api.routes.scans import router as scans_router
from app.api.routes.settings import router as settings_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.scanner.nmap_service import scanner_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize the scanner on startup; clean up on shutdown."""
    scanner_service.initialize()
    try:
        yield
    finally:
        await scanner_service.shutdown()


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    settings = get_settings()

    if settings.APP_ENV.strip().lower() in {"prod", "production"} and not settings.SESSION_COOKIE_SECURE:
        raise RuntimeError("SESSION_COOKIE_SECURE=true is required when APP_ENV is production.")

    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Backend API for VulnScanner — a security vulnerability management "
            "platform.  Provides endpoints for health monitoring, asset management, "
            "scan orchestration, vulnerability tracking, and reporting."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ─────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────────────────────
    app.include_router(health_router, prefix="/api/v1", tags=["Health"])
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(
        admin_router,
        prefix="/api/v1/admin",
        tags=["Administration"],
        dependencies=[Depends(require_admin)],
    )
    protected = [Depends(require_authentication)]
    app.include_router(assets_router, prefix="/api/v1/assets", tags=["Assets"], dependencies=protected)
    app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"], dependencies=protected)
    app.include_router(
        discoveries_router,
        prefix="/api/v1/discoveries",
        tags=["Network Discovery"],
        dependencies=protected,
    )
    app.include_router(
        authorized_targets_router,
        prefix="/api/v1/authorized-targets",
        tags=["Authorization"],
        dependencies=protected,
    )
    app.include_router(
        scan_results_router,
        prefix="/api/v1/scan-results",
        tags=["Scan Results"],
        dependencies=protected,
    )
    app.include_router(
        vulnerabilities_router,
        prefix="/api/v1/vulnerabilities",
        tags=["Vulnerabilities"],
        dependencies=protected,
    )
    app.include_router(
        dashboard_router,
        prefix="/api/v1/dashboard",
        tags=["Dashboard"],
        dependencies=protected,
    )
    app.include_router(
        reports_router,
        prefix="/api/v1/reports",
        tags=["Reports"],
        dependencies=protected,
    )
    app.include_router(
        settings_router,
        prefix="/api/v1/settings",
        tags=["Settings"],
        dependencies=[Depends(require_admin)],
    )

    # ── Root welcome ─────────────────────────────────────────────────────
    @app.get("/", tags=["Root"], summary="API welcome")
    def root() -> dict[str, str]:
        """Return a welcome message with a pointer to the docs."""
        return {
            "message": f"Welcome to {settings.APP_NAME}",
            "version": settings.APP_VERSION,
            "docs": "/docs",
        }

    return app


app = create_app()
