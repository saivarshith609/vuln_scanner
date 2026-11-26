# Backend Production Preparation Report

**Project**: VulnScanner FastAPI Backend  
**Date**: 2026-11-26  
**Scope**: Inspection and production deployment preparation for the existing FastAPI backend (`backend/`) targeting Render (backend hosting) and Supabase (hosted PostgreSQL), paired with the Vercel-hosted React + Vite frontend.

---

## 1. Project Inspection

### Backend Folder Structure
```text
backend/
├── .env                          # Local development secrets (git-ignored)
├── .env.example                  # Placeholder environment template
├── .gitignore
├── README.md
├── alembic.ini                   # Alembic migration configuration
├── requirements.txt              # Pinned Python dependencies
├── alembic/
│   ├── env.py                    # Reads DATABASE_URL from app.core.config.get_settings()
│   ├── script.py.mako
│   └── versions/                 # 10 migration revision scripts
├── app/
│   ├── __init__.py
│   ├── cli.py                    # Local admin CLI (create-admin, provision-api-key, rotate-api-key)
│   ├── main.py                   # FastAPI application factory (create_app) and app instance
│   ├── api/
│   │   └── routes/               # admin, assets, auth, authorized_targets, dashboard,
│   │                             # discoveries, health, reports, scan_results, scans,
│   │                             # settings, vulnerabilities
│   ├── core/                     # audit, auth, config, passwords (Argon2id), secrets (Fernet/scrypt)
│   ├── db/                       # base, session (lazy SQLAlchemy engine & SessionLocal)
│   ├── models/                   # asset, audit_log, authorized_target, platform_setting,
│   │                             # report, scan, scan_result, user, vulnerability
│   ├── scanner/                  # auth_service, nmap_env, nmap_service, service,
│   │                             # target_validator, xml_parser
│   └── schemas/                  # Pydantic v2 request/response schemas
└── tests/                        # 16 pytest test modules
```

### FastAPI Entry Point
- **File**: `backend/app/main.py`
- **Factory & Instance**: `create_app()` builds the `FastAPI` application (with `lifespan` initializing and shutting down `scanner_service`) and exposes `app = create_app()`.
- **ASGI Target** (when run from `backend/`): `app.main:app`

### Python Version
- **Observed Local Runtime**: Python `3.13.7` (`backend/venv/Scripts/python.exe`)

### Installed Dependencies (`backend/requirements.txt`)
| Package | Pinned Version | Role |
|---|---|---|
| `fastapi` | `0.115.12` | Web API framework |
| `uvicorn[standard]` | `0.34.3` | ASGI server |
| `pydantic` | `2.11.3` | Request/response validation |
| `pydantic-settings` | `2.9.1` | `.env` and environment variable configuration |
| `python-dotenv` | `1.1.0` | `.env` file loading support |
| `httpx` | `0.28.1` | HTTP client (used by FastAPI `TestClient`) |
| `pytest` | `8.4.1` | Test runner |
| `pytest-asyncio` | `1.4.1` | Async test support |
| `sqlalchemy` | `2.0.41` | ORM and database engine |
| `psycopg[binary]` | `3.2.9` | Psycopg 3 PostgreSQL driver (binary wheel) |
| `alembic` | `1.15.2` | Schema migrations |
| `cryptography` | `46.0.3` | Argon2id password hashing & Fernet secret encryption |

### Database Architecture
- **ORM**: SQLAlchemy 2.x (`backend/app/db/base.py`, `backend/app/db/session.py`)
- **Driver**: Psycopg 3 (`postgresql+psycopg://`)
- **Session Management**: Lazy engine initialization via `_init_engine()`, `pool_pre_ping=True`, `autocommit=False`, `autoflush=False`, yielded per request via `get_db()`.
- **Models**: `Asset`, `AuditLog`, `AuthorizedTarget`, `OperatorSession`, `PlatformApiKey`, `PlatformSetting`, `Report`, `Scan`, `ScanResult`, `User`, `Vulnerability`.

---

## 2. Files Modified

| File Path | Changes Made | Reason for Modification |
|---|---|---|
| `backend/app/core/config.py` | Added `@field_validator("DATABASE_URL")` to normalize `postgres://` and `postgresql://` prefixes to `postgresql+psycopg://`; updated `cors_origin_list` to strip trailing slashes (`rstrip("/")`). | Hosted PostgreSQL providers (Render, Supabase, etc.) often supply `postgres://` or `postgresql://` URLs without `+psycopg`, which otherwise fail under SQLAlchemy + Psycopg 3. Trailing slashes in `CORS_ORIGINS` break browser `Origin` matching. |
| `backend/.env.example` | Documented all backend environment variables (`APP_*`, `API_*`, `CORS_ORIGINS`, `DATABASE_URL`, `INTEGRATION_ENCRYPTION_KEY`, `SESSION_COOKIE_*`, `NMAP_*`, `DISCOVERY_*`) with placeholder values and production notes. | Ensure all required and optional production settings are documented without hardcoding any real secrets or credentials. |
| `backend/tests/test_health.py` | Added `TestProductionConfig` (`test_normalizes_hosted_postgres_urls_for_psycopg3`, `test_strips_trailing_slashes_from_cors_origins`). | Verify URL driver normalization and CORS origin normalization with automated tests. |

### Files Inspected Only (Not Modified)
- `backend/requirements.txt`
- `backend/alembic.ini`
- `backend/alembic/env.py`
- `backend/app/main.py`
- `backend/app/core/auth.py`
- `backend/app/core/secrets.py`
- `backend/app/db/session.py`
- `backend/app/scanner/nmap_env.py`
- `backend/app/scanner/nmap_service.py`
- `backend/tests/test_phase101_auth.py`

*(Note: `backend/.env` and the local PostgreSQL database were not modified.)*

---

## 3. Environment Configuration

| Variable Name | Purpose | Required / Optional | Where to Configure |
|---|---|---|---|
| `APP_ENV` | Runtime environment (`development` or `production`). Disables SQL `echo` in production and enforces `SESSION_COOKIE_SECURE=true`. | **Required** (`production`) | Render (Backend Env Vars) |
| `DATABASE_URL` | PostgreSQL connection string (`postgresql+psycopg://...`, `postgresql://...`, or `postgres://...`, with `?sslmode=require` for hosted DBs). | **Required** | Supabase (source) → Render (Backend Env Vars) |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins without trailing slashes (e.g. `https://<app>.vercel.app`). | **Required** | Render (Backend Env Vars) |
| `SESSION_COOKIE_SECURE` | Sets the `Secure` flag on session and CSRF cookies. Must be `true` when `APP_ENV=production` (startup raises `RuntimeError` otherwise). | **Required** (`true`) | Render (Backend Env Vars) |
| `INTEGRATION_ENCRYPTION_KEY` | Fernet key used to encrypt Jira, Slack, and Splunk integration secrets at rest. | **Required** (before saving integration secrets) | Render (Backend Env Vars) |
| `APP_NAME` | Application title shown in OpenAPI docs and health responses (`VulnScanner API`). | Optional | Render (Backend Env Vars) |
| `APP_VERSION` | Application version string (`1.0.0`). | Optional | Render (Backend Env Vars) |
| `API_HOST` | Bind host (`0.0.0.0` in containers/Render via CLI flag). | Optional | Render Start Command / Env |
| `API_PORT` | Bind port (Render injects `PORT` dynamically). | Optional | Render (managed via `$PORT`) |
| `SESSION_COOKIE_NAME` | Name of the HttpOnly session cookie (default `vulnscanner_session`). | Optional | Render (Backend Env Vars) |
| `NMAP_EXECUTABLE` | Explicit path to the `nmap` binary (leave blank to auto-detect on `PATH`). | Optional | Render (Backend Env Vars) |
| `NMAP_TIMEOUT_SECONDS` | Hard subprocess timeout in seconds (default `600`). | Optional | Render (Backend Env Vars) |
| `NMAP_MAX_CONCURRENT` | Maximum concurrent Nmap scans (default `3`). | Optional | Render (Backend Env Vars) |
| `NMAP_MAX_OUTPUT_BYTES` | Maximum buffered Nmap XML output in bytes (default `10485760`). | Optional | Render (Backend Env Vars) |
| `DISCOVERY_MAX_ADDRESSES` | Maximum IP addresses allowed per network discovery scope (default `4096`). | Optional | Render (Backend Env Vars) |
| `DISCOVERY_TIMEOUT_SECONDS` | Timeout in seconds for host discovery runs (default `300`). | Optional | Render (Backend Env Vars) |

---

## 4. Database Readiness

- **Supabase PostgreSQL Compatibility**: Compatible with Supabase PostgreSQL (standard PostgreSQL wire protocol, UUID primary keys, `DateTime(timezone=True)`, JSON/JSONB-free standard SQLAlchemy types, and `CheckConstraint`s).
- **`DATABASE_URL` Format**:
  - Normalized in `backend/app/core/config.py`: `postgres://...` and `postgresql://...` are automatically converted to `postgresql+psycopg://...`.
  - Include `?sslmode=require` for Supabase connections (e.g., `postgresql+psycopg://USER:PASSWORD@HOST:5432/postgres?sslmode=require`).
  - **Note on Supabase Connection Pooling**: If using Supabase's PgBouncer transaction pooler (port `6543`), prepared statements can conflict unless disabled; using Supabase's direct connection or session pooler (port `5432`) is recommended for Alembic migrations and SQLAlchemy 2 + Psycopg 3.
- **SQLAlchemy & Psycopg Configuration**:
  - `backend/app/db/session.py` uses `create_engine(settings.DATABASE_URL, pool_pre_ping=True, echo=(settings.APP_ENV == "development"))`.
  - `psycopg[binary]==3.2.9` is pinned in `backend/requirements.txt` (no OS `libpq-dev` build dependency required).
- **Alembic Migration Status**:
  - `backend/alembic/env.py` imports `app.core.config.get_settings()` and `app.models`, overriding `sqlalchemy.url` with `settings.DATABASE_URL`.
  - 10 migration scripts exist under `backend/alembic/versions/` (`0ec56e5f40b3` through `d4a6f28c91b3`, `a72e6b91c4d2`, etc.).
- **Safe Migration Instructions**:
  1. Set `DATABASE_URL` in the target environment (or shell pointing to Supabase).
  2. From `backend/`, run:
     ```bash
     alembic upgrade head
     ```
  3. Verify current revision:
     ```bash
     alembic current
     ```
  4. Bootstrap the first administrator account once:
     ```bash
     python -m app.cli create-admin
     ```
- **Backup & Rollback Considerations**:
  - Take a Supabase database snapshot/backup before running migrations on a populated database.
  - Roll back one revision if needed via `alembic downgrade -1` (never run `alembic downgrade base` on production data).

---

## 5. Render Deployment Readiness

- **Service Type**: **Web Service** (Docker runtime recommended if Nmap scanning is required; native Python runtime otherwise).
- **Root Directory**: `backend`
- **Build Command** (native Python):
  ```bash
  pip install -r requirements.txt
  ```
- **Start Command**:
  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
  ```
  *(Single worker only — `NmapScannerService` stores active scan `asyncio.Task`s in process memory.)*
- **Python Version**: Set `PYTHON_VERSION=3.13.7` (or `3.12`/`3.13`) in Render if using native Python.
- **Required Environment Variables**: `APP_ENV=production`, `SESSION_COOKIE_SECURE=true`, `DATABASE_URL`, `CORS_ORIGINS`, `INTEGRATION_ENCRYPTION_KEY`.
- **Health-Check Endpoint**: `/api/v1/health` (liveness) and `/api/v1/health/database` (PostgreSQL connectivity).

---

## 6. Security Review

- **CORS Configuration**: `CORSMiddleware` in `backend/app/main.py` sets `allow_origins=settings.cors_origin_list` and `allow_credentials=True`. Trailing slashes are now stripped from `CORS_ORIGINS`.
- **Secure Session Cookies**: `backend/app/main.py` enforces `SESSION_COOKIE_SECURE=true` whenever `APP_ENV` is `prod` or `production`. Session cookies (`vulnscanner_session`) are `HttpOnly` and `Secure` in production.
- **SameSite Configuration**: `backend/app/core/auth.py` sets `samesite="strict"` on both `vulnscanner_session` and `vulnscanner_csrf`.
- **CSRF Protection**: Double-submit CSRF cookie (`vulnscanner_csrf`) validated against `X-CSRF-Token` header on all state-changing authenticated requests (`POST`, `PUT`, `PATCH`, `DELETE`).
- **HTTPS Requirements**: Both the Vercel frontend and Render backend must be served over HTTPS so `Secure` cookies are accepted by browsers.
- **Authentication & Authorization Preservation**: Argon2id password hashing (`backend/app/core/passwords.py`), server-side session storage (`OperatorSession`), `require_authentication`, `require_admin`, and `require_owner` remain completely intact.

---

## 7. Nmap Compatibility

- **Installation Requirements**: `NmapEnvironment.detect()` in `backend/app/scanner/nmap_env.py` locates `nmap` on `PATH` (or via `NMAP_EXECUTABLE`) and verifies `nmap --version` with `shell=False`.
- **Render OS Compatibility**:
  - Render's **native Python environment** does **not** include `nmap` and does not permit `apt-get install` in build commands.
  - A **Docker-based Render Web Service** (e.g., `python:3.13-slim` with `apt-get update && apt-get install -y nmap`) is required to make the `nmap` binary available.
- **Network Scanning Limitations**:
  - Scan profiles (`-sV -T3 -F`, `-sn`, `-sV -T3 -p-`) avoid root-only flags (`-sU`, `-O`, `-A`), so unprivileged TCP connect scans work inside containers.
  - Cloud providers (including Render) restrict or prohibit unsolicited external port scanning under Acceptable Use Policies; scanning must remain restricted to explicitly authorized targets.
- **Recommended Production Approach**:
  - Deploy the backend with a `Dockerfile` that installs `nmap` if cloud-hosted scanning is desired, or run a dedicated authorized scanner worker in an allowed network while keeping API/database on Render + Supabase.

---

## 8. Testing Results

| Check | Scope | Result | Notes |
|---|---|---|---|
| Targeted Backend Test Suite | `test_health.py`, `test_database.py`, `test_phase101_auth.py`, `test_user_authentication.py`, `test_api.py` | **PASSED (122 passed, 1 warning)** | Executed after final edits (`PYTHONPATH=.` from `backend/`). |
| Authentication & CSRF Tests | Included in `test_phase101_auth.py` & `test_user_authentication.py` | **PASSED** | Covers Argon2id login, admin/normal role separation, `SESSION_COOKIE_SECURE=true` production guard, CSRF double-submit, and ownership checks. |
| Database Schema & Health Tests | Included in `test_database.py` & `test_health.py` | **PASSED** | Covers schema validation and mocked DB health checks (`/api/v1/health`, `/api/v1/health/database`). |
| Production Config Checks | `TestProductionConfig` in `test_health.py` | **PASSED** | Verifies `postgres://`/`postgresql://` → `postgresql+psycopg://` normalization and `CORS_ORIGINS` trailing-slash stripping. |
| Remaining Backend Test Files | `test_admin_control_center.py`, `test_network_discovery.py`, `test_phase10_settings.py`, `test_phase42.py`, `test_phase6.py`, `test_phase7.py`, `test_phase8.py`, `test_phase92_reports.py`, `test_phase93_export.py`, `test_scan_reports.py`, `test_scanner.py` | **NOT TESTED** (after final edit) | Not re-run after final edits to `config.py`. |
| Alembic Migration Against Supabase | `alembic upgrade head` on hosted PostgreSQL | **NOT TESTED** | No live Supabase database has been created yet. |
| Live Render Startup & Health Probe | `uvicorn app.main:app` in production container | **NOT TESTED** | Pending Render service creation. |

---

## 9. Remaining Blockers

1. **Cross-Origin `SameSite=Strict` Cookie & CSRF Cookie Domain Mismatch (`*.vercel.app` ↔ `*.onrender.com`)**:
   - **Issue**: `vulnscanner_session` and `vulnscanner_csrf` use `samesite="strict"`, and the frontend reads `vulnscanner_csrf` from `document.cookie` on the Vercel domain. Across separate public-suffix domains (`vercel.app` vs `onrender.com`), browsers block `SameSite=Strict` cookies on cross-origin `fetch` calls and cannot read backend-domain cookies via `document.cookie`.
   - **Next Action**: Configure a same-origin proxy (e.g., Vercel `/api/*` rewrite/proxy to Render or a shared custom domain reverse proxy) so frontend and backend requests share the same origin without weakening `SameSite=Strict` or CSRF.
2. **Nmap Binary Missing on Render Native Python Runtime**:
   - **Issue**: Render's native Python buildpack does not provide `nmap`.
   - **Next Action**: Add a `backend/Dockerfile` installing `nmap` (on `python:3.13-slim`) and deploy Render as a Docker Web Service if live scanning is required in production.
3. **Supabase Database Not Yet Provisioned**:
   - **Issue**: Production `DATABASE_URL` does not yet exist, and migrations + initial admin account have not been applied to a hosted DB.
   - **Next Action**: Create the Supabase project, run `alembic upgrade head`, and run `python -m app.cli create-admin`.

---

## 10. Final Deployment Readiness

| Area | Status | Notes |
|---|---|---|
| FastAPI App & Entry Point (`app.main:app`) | **READY** | Clean startup, lifespan, and health endpoints. |
| Dependencies (`requirements.txt`) | **READY** | All packages pinned, Psycopg 3 binary included. |
| `DATABASE_URL` & SQLAlchemy / Alembic Config | **READY** | Hosted `postgres://` / `postgresql://` URLs normalized for Psycopg 3. |
| Environment Template (`backend/.env.example`) | **READY** | Complete placeholders, no hardcoded secrets. |
| Production Environment Variables | **NEEDS CONFIGURATION** | Must be set in Render (`APP_ENV`, `SESSION_COOKIE_SECURE`, `DATABASE_URL`, `CORS_ORIGINS`, `INTEGRATION_ENCRYPTION_KEY`). |
| Supabase Migrations & Admin Bootstrap | **NOT TESTED** | Requires creating Supabase DB and running `alembic upgrade head` + `create-admin`. |
| Cross-Origin Cookies & CSRF (Vercel ↔ Render) | **BLOCKED** | Requires same-origin proxy/rewrite or custom domain so `SameSite=Strict` and `document.cookie` CSRF work. |
| Nmap Scanning on Render | **BLOCKED** | Requires a Docker Web Service with `nmap` installed (unavailable in Render native Python). |

---

### Next-Phase Handoff Summary: Supabase Database Creation & Configuration

1. Create a new **Supabase** project and copy the PostgreSQL connection string (prefer the direct/session pooler on port `5432` with `?sslmode=require`).
2. Locally (without modifying your local database), set `DATABASE_URL` in your terminal to the Supabase connection string and run from `backend/`:
   ```bash
   alembic upgrade head
   python -m app.cli create-admin
   ```
3. Generate a production `INTEGRATION_ENCRYPTION_KEY` via:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
4. Store `DATABASE_URL`, `INTEGRATION_ENCRYPTION_KEY`, `APP_ENV=production`, `SESSION_COOKIE_SECURE=true`, and `CORS_ORIGINS` in Render's environment variables.
