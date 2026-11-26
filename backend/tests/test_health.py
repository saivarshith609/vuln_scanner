"""
VulnScanner API — Test suite for the health and root endpoints.
"""

from fastapi.testclient import TestClient

from app.main import create_app


def get_client() -> TestClient:
    """Create a fresh test client from the application factory."""
    return TestClient(create_app())


# ── Root endpoint ────────────────────────────────────────────────────────────


class TestRootEndpoint:
    """Tests for GET /"""

    def test_root_returns_200(self) -> None:
        client = get_client()
        response = client.get("/")
        assert response.status_code == 200

    def test_root_contains_welcome_message(self) -> None:
        client = get_client()
        data = client.get("/").json()
        assert "message" in data
        assert "VulnScanner" in data["message"]

    def test_root_contains_docs_link(self) -> None:
        client = get_client()
        data = client.get("/").json()
        assert data.get("docs") == "/docs"

    def test_root_contains_version(self) -> None:
        client = get_client()
        data = client.get("/").json()
        assert data.get("version") == "1.0.0"


# ── Health endpoint ──────────────────────────────────────────────────────────


class TestHealthEndpoint:
    """Tests for GET /api/v1/health"""

    def test_health_returns_200(self) -> None:
        client = get_client()
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_schema(self) -> None:
        client = get_client()
        data = client.get("/api/v1/health").json()
        assert set(data.keys()) == {"status", "application", "version"}

    def test_health_status_is_healthy(self) -> None:
        client = get_client()
        data = client.get("/api/v1/health").json()
        assert data["status"] == "healthy"

    def test_health_application_name(self) -> None:
        client = get_client()
        data = client.get("/api/v1/health").json()
        assert data["application"] == "VulnScanner API"

    def test_health_version(self) -> None:
        client = get_client()
        data = client.get("/api/v1/health").json()
        assert data["version"] == "1.0.0"


# ── 404 handling ─────────────────────────────────────────────────────────────


class TestNotFound:
    """Verify unknown routes return 404."""

    def test_unknown_route_returns_404(self) -> None:
        client = get_client()
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404

    def test_completely_unknown_path_returns_404(self) -> None:
        client = get_client()
        response = client.get("/this/does/not/exist")
        assert response.status_code == 404


# ── Import smoke test ───────────────────────────────────────────────────────


class TestAppImport:
    """Verify the application module can be imported cleanly."""

    def test_app_module_imports(self) -> None:
        from app.main import app  # noqa: F811
        assert app is not None

    def test_create_app_returns_fastapi(self) -> None:
        from fastapi import FastAPI
        app = create_app()
        assert isinstance(app, FastAPI)
