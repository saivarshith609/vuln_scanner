# Render + Supabase Production Preparation Report

**Project**: VulnScanner  
**Date**: 2026-11-26  
**Target Architecture**:
- **Frontend**: Render Static Site (React + Vite)
- **Backend**: Render Web Service (FastAPI)
- **Database**: Supabase PostgreSQL
- **Source Control**: Existing GitHub repository

---

## 1. Existing Hosting Configuration Inspected

- **`vercel.json`** (previously created at repository root): Configured Vercel's `vite` framework preset, build/install/output commands, and SPA rewrite (`/(.*) -> /index.html`). No other Vercel configuration files or references existed in `src/`, `backend/`, `.env.example`, or `README.md`.
- **`src/services/api.ts`**: Uses `resolveApiBaseUrl()` to read `import.meta.env.VITE_API_BASE_URL`, strips trailing slashes, restricts the `http://localhost:8000/api/v1` fallback to non-production (`!PROD || MODE === 'test'`), and fails closed with an `ApiError` if `VITE_API_BASE_URL` is unset in production.
- **`.env` & `.env.example`**: Local `.env` sets `VITE_API_BASE_URL=http://localhost:8000/api/v1` (git-ignored).
- **`backend/app/core/config.py` & `backend/.env.example`**: Pydantic `Settings` loads environment variables, normalizes `DATABASE_URL` (`postgres://` / `postgresql://` → `postgresql+psycopg://`), and parses `CORS_ORIGINS` (stripping trailing slashes).
- **`backend/app/core/auth.py` & `backend/app/main.py`**: Enforces `SESSION_COOKIE_SECURE=true` in production, sets `HttpOnly` session cookies and double-submit CSRF cookies with `SameSite=Strict`, and enables `CORSMiddleware(..., allow_credentials=True)`.
- **`backend/app/db/session.py` & `backend/alembic/env.py`**: Lazy SQLAlchemy 2.x engine with `pool_pre_ping=True`, Psycopg 3 (`psycopg[binary]==3.2.9`), and Alembic reading `get_settings().DATABASE_URL`.

---

## 2. Files Modified and Exact Changes

| File Path | Action | Exact Changes |
|---|---|---|
| `vercel.json` | **Removed** | Deleted obsolete Vercel deployment configuration file. |
| `backend/.env.example` | **Updated** | Updated `CORS_ORIGINS` production example comment from Vercel to `https://your-frontend.onrender.com`; documented all backend and scanner env vars with placeholder values only. |
| `src/__tests__/phase12ApiService.test.ts` | **Updated** | Added assertion verifying `resolveApiBaseUrl({ configuredUrl: '/api/v1/', isProduction: true })` resolves cleanly to `'/api/v1'` for Render Static Site same-origin `/api/*` rewrites. |
| `RENDER_PRODUCTION_PREPARATION_REPORT.md` | **Created** | This preparation report. |

*(Preserved from prior preparation: `src/services/api.ts` `resolveApiBaseUrl()` and `backend/app/core/config.py` `DATABASE_URL` + `CORS_ORIGINS` normalization. Local `.env`, `backend/.env`, local PostgreSQL data, authentication, and backend routes were not modified.)*

---

## 3. Render Frontend Configuration (Static Site)

- **Service Type**: Render **Static Site**
- **Root Directory**: `.` *(repository root)*
- **Build Command**: `npm install && npm run build`
- **Publish Directory**: `dist`
- **Environment Variables**:
  - `VITE_API_BASE_URL=/api/v1` *(recommended when using the Render Static Site `/api/*` rewrite rule below so cookies and CSRF remain same-origin)*
- **Render Redirects / Rewrites** (configured in Render Static Site → **Redirects/Rewrites**, in this exact order):
  1. **API Proxy Rewrite** *(first, so `/api/*` is not caught by the SPA fallback)*:
     - **Source**: `/api/*`
     - **Destination**: `https://<your-backend-service>.onrender.com/api/*`
     - **Action**: `Rewrite`
  2. **SPA Client-Side Routing Fallback**:
     - **Source**: `/*`
     - **Destination**: `/index.html`
     - **Action**: `Rewrite`

---

## 4. Render Backend Configuration (Web Service)

- **Service Type**: Render **Web Service**
  - **Runtime**: **Docker** *(required if live Nmap scanning is needed)*, or **Python 3** *(if Nmap scanning is not required in the cloud)*
- **Root Directory**: `backend`
- **Build Command** *(Python 3 runtime)*: `pip install -r requirements.txt`
- **ASGI Application**: `app.main:app`
- **Start Command**:
  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
  ```
  *(Use a single worker — `NmapScannerService` tracks active scan `asyncio.Task`s in process memory.)*
- **Health Check Path**: `/api/v1/health`

---

## 5. Required Environment Variables and Their Purposes

### Frontend (Render Static Site)
| Variable | Required | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | **Required** | Base URL for FastAPI requests. Set to `/api/v1` when using the Render Static Site `/api/*` rewrite rule (recommended). |

### Backend (Render Web Service)
| Variable | Required | Purpose |
|---|---|---|
| `APP_ENV` | **Required** (`production`) | Enables production mode, disables SQL query `echo`, and enforces `SESSION_COOKIE_SECURE=true`. |
| `SESSION_COOKIE_SECURE` | **Required** (`true`) | Marks `vulnscanner_session` and `vulnscanner_csrf` cookies as `Secure` for HTTPS. Startup raises `RuntimeError` if `false` in production. |
| `DATABASE_URL` | **Required** | Supabase PostgreSQL connection string (`postgresql+psycopg://...`, `postgresql://...`, or `postgres://...` with `?sslmode=require`). |
| `CORS_ORIGINS` | **Required** | Allowed frontend origin(s), e.g. `https://<your-frontend>.onrender.com` (comma-separated, no trailing slashes). |
| `INTEGRATION_ENCRYPTION_KEY` | **Required** (for integration secrets) | Fernet key for encrypting Jira/Slack/Splunk credentials in PostgreSQL. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. |
| `PYTHON_VERSION` | Optional (`3.13.7`) | Pins Python runtime version on Render native Python Web Service. |
| `SESSION_COOKIE_NAME` | Optional (`vulnscanner_session`) | Name of the HttpOnly server-session cookie. |
| `NMAP_EXECUTABLE` | Optional | Explicit path to `nmap` binary if not on `PATH`. |
| `NMAP_TIMEOUT_SECONDS` | Optional (`600`) | Hard timeout in seconds for Nmap subprocesses. |
| `NMAP_MAX_CONCURRENT` | Optional (`3`) | Maximum concurrent Nmap scans. |
| `NMAP_MAX_OUTPUT_BYTES` | Optional (`10485760`) | Maximum buffered Nmap XML output size in bytes. |
| `DISCOVERY_MAX_ADDRESSES` | Optional (`4096`) | Maximum IP addresses per network discovery scope. |
| `DISCOVERY_TIMEOUT_SECONDS` | Optional (`300`) | Timeout in seconds for network discovery runs. |

---

## 6. Authentication, Cookie, CORS, and CSRF Compatibility

- **Why a Same-Origin `/api/*` Rewrite on Render Static Site Is Essential**:
  - `*.onrender.com` is on the Public Suffix List, so `https://<frontend>.onrender.com` and `https://<backend>.onrender.com` are treated by browsers as **cross-site** if called directly.
  - `backend/app/core/auth.py` sets both `vulnscanner_session` (`HttpOnly`) and `vulnscanner_csrf` with `samesite="strict"`, and `src/services/api.ts` reads `vulnscanner_csrf` from `document.cookie` to send `X-CSRF-Token`.
  - Calling `https://<backend>.onrender.com` directly from `https://<frontend>.onrender.com` would fail because browsers block `SameSite=Strict` cookies on cross-site `fetch` requests and `document.cookie` on the frontend cannot read cookies issued for the backend's hostname.
- **How the Render Static Site Rewrite Solves This Without Weakening Security**:
  - With the `/api/*` → `https://<backend>.onrender.com/api/*` Rewrite rule on the Render Static Site and `VITE_API_BASE_URL=/api/v1`:
    - All browser requests go to `https://<frontend>.onrender.com/api/v1/...` (strictly **same-origin**).
    - `HttpOnly`, `Secure`, and `SameSite=Strict` remain enforced on `vulnscanner_session`.
    - `document.cookie` on `https://<frontend>.onrender.com` reads `vulnscanner_csrf` and sends `X-CSRF-Token` on all mutating requests.
    - Argon2id password hashing, admin/user role separation, ownership checks, and `require_authentication` / `require_admin` / `require_owner` remain 100% preserved.

---

## 7. Supabase Database Readiness

- **SQLAlchemy & Psycopg 3**: `backend/requirements.txt` pins `sqlalchemy==2.0.41` and `psycopg[binary]==3.2.9`. `backend/app/db/session.py` configures `pool_pre_ping=True`.
- **URL Normalization**: `backend/app/core/config.py` normalizes `postgres://` and `postgresql://` to `postgresql+psycopg://`, matching Supabase connection strings.
- **Connection Mode Recommendation**: Use Supabase's direct connection or session pooler (port `5432`) with `?sslmode=require` for Alembic migrations and SQLAlchemy 2 + Psycopg 3 prepared statements.
- **Alembic Migrations**: 10 migration revisions are present under `backend/alembic/versions/`, and `backend/alembic/env.py` reads `get_settings().DATABASE_URL`.
- **Migration & Bootstrap Commands** (run from `backend/` once Supabase `DATABASE_URL` is available):
  ```bash
  alembic upgrade head
  python -m app.cli create-admin
  ```

---

## 8. Nmap / Docker Compatibility

- **Docker Requirement**: Render's native Python Web Service does **not** pre-install `nmap` and does not permit `apt-get install` in native build commands.
  - **If live Nmap scanning is required on Render**: **Docker is required** (`python:3.13-slim` + `apt-get update && apt-get install -y nmap` + `pip install -r requirements.txt` + `uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}`).
  - **If deployed on native Python without Docker**: The API, authentication, dashboard, reports, and database features all work, but Nmap scan/discovery execution will fail with `NmapNotAvailableError`.
- **Scan Profiles & Cloud Policy**: Scan profiles use unprivileged flags (`-sV`, `-sn`, `-oX -`) and block root-only flags (`-sU`, `-O`, `-A`), so unprivileged scanning works inside Docker; all targets must comply with Render's Acceptable Use Policy and authorized-target rules.

---

## 9. Tests and Build Results

All tests and builds below were executed after the final file edits:

- **Complete Frontend Test Suite** (`npx vitest run`):
  - **30 test files passed (30/30)**
  - **267 tests passed (267/267)**, 0 failed
- **TypeScript Check & Production Build** (`tsc -b && vite build`):
  - **PASSED** (`tsc -b --noEmit` exited 0; `vite build` transformed 3,152 modules and built `dist/` in `2.02s`)
- **Complete Backend Test Suite** (`pytest tests -v` from `backend/` with `PYTHONPATH=.`):
  - **337 tests passed (337/337)**, 0 failed (1 deprecation warning from `starlette.testclient`)
- **Live Supabase Migration & Live Render Deployment**:
  - **NOT TESTED** (per instructions, no hosted database or Render service was created/deployed).

---

## 10. Remaining Blockers

1. **Same-Origin `/api/*` Rewrite Rule Not Yet Applied in Render**: Must be configured in the Render Static Site dashboard (`VITE_API_BASE_URL=/api/v1` + `/api/*` rewrite to the Render Web Service) so `SameSite=Strict` and double-submit CSRF work in production.
2. **Docker Configuration for Nmap (If Cloud Scanning Is Needed)**: No `backend/Dockerfile` exists yet; if live Nmap scans will run from Render, a `Dockerfile` installing `nmap` is needed before deploying the Render Web Service as Docker.
3. **Supabase Database & Production Env Vars Not Yet Provisioned**: Supabase database creation, `alembic upgrade head`, `python -m app.cli create-admin`, and Render environment variable configuration are pending.

---

## 11. Manual Deployment Instructions (Overview for Next Phase)

1. **Create Supabase PostgreSQL Project**: Copy the port-`5432` PostgreSQL URL (`?sslmode=require`), run `alembic upgrade head` and `python -m app.cli create-admin` from `backend/`.
2. **Create Render Web Service (Backend)**:
   - Connect GitHub repo, set Root Directory to `backend`, set Build & Start commands (or Docker), configure required env vars (`APP_ENV=production`, `SESSION_COOKIE_SECURE=true`, `DATABASE_URL`, `CORS_ORIGINS`, `INTEGRATION_ENCRYPTION_KEY`), and set Health Check Path to `/api/v1/health`.
3. **Create Render Static Site (Frontend)**:
   - Connect GitHub repo, set Root Directory to `.`, Build Command to `npm install && npm run build`, Publish Directory to `dist`, set `VITE_API_BASE_URL=/api/v1`, and add the two Rewrite rules (`/api/*` → backend `/api/*`, then `/*` → `/index.html`).

---

## 12. Final Status

| Area | Status |
|---|---|
| Frontend Code & Production Build (`dist/`) | **READY** |
| Backend Code, Auth, CSRF, & SQLAlchemy/Psycopg 3 | **READY** |
| Local Test Suites (267 Frontend + 337 Backend) | **READY** |
| Render Static Site & Web Service Configuration | **NEEDS CONFIGURATION** |
| Supabase PostgreSQL Provisioning & Migrations | **NOT TESTED** |
| Live Nmap Scanning on Render (without Dockerfile) | **BLOCKED** (requires `backend/Dockerfile` with `nmap` if enabled on Render) |

---

*Preparation complete. Waiting for your approval before proceeding to Supabase database creation and Render hosting setup.*
