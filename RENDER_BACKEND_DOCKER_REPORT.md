# Render Backend Docker Deployment Report

**Project**: VulnScanner FastAPI Backend  
**Date**: 2026-11-26  
**Target Platform**: Render Web Service (Docker) + Supabase PostgreSQL

---

## 1. Files Created and Modified

| File Path | Action | Purpose |
|---|---|---|
| `backend/Dockerfile` | **Created** | Production Docker image definition using `python:3.13-slim`, installing `nmap` + `ca-certificates` + `requirements.txt`, running as unprivileged `appuser`, and launching single-worker Uvicorn on `0.0.0.0:${PORT:-8000}`. |
| `backend/.dockerignore` | **Created** | Excludes `.env`, `.env.*` (except `!.env.example`), `venv/`, `.venv/`, `env/`, `__pycache__/`, `*.py[cod]`, `.pytest_cache/`, `.coverage`, `htmlcov/`, `.git/`, IDE files, and logs from the Docker build context. |
| `RENDER_BACKEND_DOCKER_REPORT.md` | **Created** | This Docker preparation and verification report. |

*(No existing application source, auth, database, route, migration, or `.env` files were modified.)*

---

## 2. Docker Base Image and Installed Dependencies

- **Base Image**: `python:3.13-slim`
- **OS Packages** (`apt-get install --no-install-recommends`):
  - `nmap` (provides `/usr/bin/nmap` on `PATH` for `NmapEnvironment.detect()`)
  - `ca-certificates` (TLS certificate verification for outbound HTTPS / database SSL)
- **Python Dependencies** (`pip install --no-cache-dir -r requirements.txt`):
  - `fastapi==0.115.12`
  - `uvicorn[standard]==0.34.3`
  - `pydantic==2.11.3`
  - `pydantic-settings==2.9.1`
  - `python-dotenv==1.1.0`
  - `httpx==0.28.1`
  - `pytest==8.4.1`, `pytest-asyncio==1.4.1`
  - `sqlalchemy==2.0.41`
  - `psycopg[binary]==3.2.9`
  - `alembic==1.15.2`
  - `cryptography==46.0.3`
- **Runtime User**: Non-root `appuser` (`useradd --create-home --shell /bin/sh appuser`).

---

## 3. Exact Render Build and Start Configuration

In **Render → New → Web Service**:
- **Environment / Runtime**: `Docker`
- **Root Directory**: `backend`
- **Dockerfile Path**: `Dockerfile` *(relative to `backend/`)*
- **Docker Build Context Directory**: `.` *(relative to `backend/`)*
- **Start Command**: *(uses `Dockerfile` `CMD` directly; do not override unless needed)*
  ```sh
  sh -c "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"
  ```
- **Health Check Path**: `/api/v1/health`
- **Migrations**: Intentionally **not** executed in `CMD` on container startup. Run `alembic upgrade head` separately against the Supabase `DATABASE_URL` before/during release.

---

## 4. Nmap Verification

- **Static / Dockerfile Verification**:
  - `backend/Dockerfile` installs `nmap` via `apt-get` and runs `RUN nmap --version` during the Docker image build so any missing/broken binary fails the build immediately.
  - `NmapEnvironment.detect()` in `backend/app/scanner/nmap_env.py` checks `shutil.which("nmap")`, which resolves `/usr/bin/nmap` on Debian slim images without needing `NMAP_EXECUTABLE` set.
  - Scan profiles (`-sV -T3 -F`, `-sn`, `-sV -T3 -p-`) avoid root-only flags (`-sU`, `-O`, `-A`), so scans execute under the non-root `appuser`.
- **Live Container Execution**:
  - **NOT TESTED** locally — Docker CLI (`29.7.2`) is installed, but the Docker Desktop Linux daemon was not running (`open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`).

---

## 5. Security Review

- **No Baked Secrets**: `backend/.dockerignore` excludes `.env`, `.env.*` (allowing only `.env.example`), `venv/`, and `.git/`. Production secrets (`DATABASE_URL`, `INTEGRATION_ENCRYPTION_KEY`, etc.) must be supplied via Render Environment Variables at runtime.
- **Least Privilege**: Container runs as unprivileged `appuser` instead of `root`.
- **Single Worker**: `--workers 1` preserves `NmapScannerService`'s in-memory `asyncio.Task` registry for scan tracking and cancellation.
- **Auth, CSRF, & Sessions Preserved**: Argon2id password hashing, `HttpOnly` + `Secure` + `SameSite=Strict` session cookies, double-submit `X-CSRF-Token` validation, `require_authentication`, `require_admin`, and `require_owner` are unchanged.
- **No Startup Migrations**: `alembic upgrade head` is not run automatically on boot.

---

## 6. Test Results and Actual Counts

| Check | Command | Result | Notes |
|---|---|---|---|
| FastAPI App Import | `python -c "from app.main import app; print('FastAPI import OK:', app.title, app.version)"` | **PASSED** | `FastAPI import OK: VulnScanner API 1.0.0` |
| Python Dependency Check | `python -m pip check` | **PASSED** | `No broken requirements found.` |
| Complete Backend Test Suite | `pytest tests -q` (from `backend/`, `PYTHONPATH=.`) | **PASSED (337 passed, 1 warning)** | Ran in `38.16s` (1 `DeprecationWarning` from `starlette.testclient`). |
| Docker Image Build (`docker build`) | `docker --version` / `docker info` | **NOT TESTED** | Docker CLI `29.7.2` present, but Docker Desktop Linux engine daemon is not running on this host. |
| `nmap --version` Inside Container | — | **NOT TESTED** | Blocked locally until Docker Desktop daemon is started (will also execute automatically during Render's Docker build). |

---

## 7. Remaining Deployment Blockers

1. **Local Docker Daemon Not Running**: Start Docker Desktop and run `docker build -t vulnscanner-api ./backend` (plus `docker run --rm vulnscanner-api nmap --version`) if you want to verify the image locally before pushing to GitHub/Render.
2. **Supabase Database & Migrations**: Provision the Supabase PostgreSQL database, run `alembic upgrade head`, and run `python -m app.cli create-admin`.
3. **Render Environment Variables & Frontend Rewrite**: Configure `APP_ENV=production`, `SESSION_COOKIE_SECURE=true`, `DATABASE_URL`, `CORS_ORIGINS`, and `INTEGRATION_ENCRYPTION_KEY` on Render, and configure the Render Static Site `/api/*` rewrite rule (`VITE_API_BASE_URL=/api/v1`) so `SameSite=Strict` cookies and double-submit CSRF remain same-origin.

---

## 8. Final Status

| Area | Status |
|---|---|
| `backend/Dockerfile` & `backend/.dockerignore` | **READY** |
| FastAPI Imports, Python Dependencies, & Backend Tests (`337 passed`) | **READY** |
| Local `docker build` & Container `nmap --version` Verification | **NOT TESTED** (Docker Desktop daemon stopped) |
| Render Service & Environment Variables | **NEEDS CONFIGURATION** |
| Supabase Database & Alembic Migrations | **NOT TESTED** |
