"""
VulnScanner API — Application configuration.

Loads settings from environment variables with sensible development defaults.
Uses pydantic-settings for validation and type coercion.
"""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Application ──────────────────────────────────────────────────────
    APP_NAME: str = "VulnScanner API"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"

    # ── Server ───────────────────────────────────────────────────────────
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    # ── CORS ─────────────────────────────────────────────────────────────
    # Comma-separated allowed origins for CORS.
    # Default matches the Vite dev server.
    CORS_ORIGINS: str = "http://localhost:5173"

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg://vulnscanner:changeme@localhost:5432/vulnscanner"

    # ── Scanner ──────────────────────────────────────────────────────────
    # Absolute path to the Nmap binary.  Leave blank to auto-detect.
    NMAP_EXECUTABLE: str = ""

    # Hard upper-bound (seconds) for any Nmap subprocess.
    NMAP_TIMEOUT_SECONDS: int = 600

    # Maximum number of Nmap scans that may run concurrently.
    NMAP_MAX_CONCURRENT: int = 3

    # Maximum bytes of Nmap XML output buffered in memory.
    NMAP_MAX_OUTPUT_BYTES: int = 10 * 1024 * 1024  # 10 MiB

    # Discovery scopes are intentionally bounded to prevent accidental or
    # abusive scans of very large networks. Both CIDRs and explicit ranges use
    # this address-count ceiling before Nmap is launched.
    DISCOVERY_MAX_ADDRESSES: int = 4096
    DISCOVERY_TIMEOUT_SECONDS: int = 300

    # Server-side key used only to encrypt database-managed integration secrets.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    INTEGRATION_ENCRYPTION_KEY: SecretStr | None = None

    # Browser session cookie. Set SESSION_COOKIE_SECURE=true behind HTTPS.
    SESSION_COOKIE_NAME: str = "vulnscanner_session"
    SESSION_COOKIE_SECURE: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse the comma-separated origins string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (parsed once per process)."""
    return Settings()
