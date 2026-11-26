# Production Dockerfile for VulnScanner FastAPI Backend (Render Docker Web Service)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install Nmap and minimal TLS/CA certificates; keep image lean
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create unprivileged user (Nmap scan profiles use non-root TCP/ping flags)
RUN useradd --create-home --shell /bin/sh appuser

# Copy backend application source (secrets and .env are excluded via .dockerignore)
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

# Bind to 0.0.0.0 and Render's dynamic $PORT with a single worker so
# NmapScannerService's in-memory asyncio task registry stays consistent.
# Migrations (alembic upgrade head) are intentionally NOT run on startup.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
