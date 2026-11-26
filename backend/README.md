# VulnScanner API — Backend

FastAPI backend for the VulnScanner security vulnerability management platform.

## Prerequisites

- **Python 3.11+** (tested with Python 3.13)
- **pip** (bundled with Python)
- **PostgreSQL 15+** (tested with PostgreSQL 18; required for live persistence)
  - Windows: Install via [PostgreSQL official installer](https://www.postgresql.org/download/windows/) or run via Docker:
    ```powershell
    docker run --name vulnscanner-postgres -e POSTGRES_USER=vulnscanner -e POSTGRES_PASSWORD=changeme -e POSTGRES_DB=vulnscanner -p 5432:5432 -d postgres:16-alpine
    ```

---

## Quick Start (Windows PowerShell)

### 1. Create a virtual environment

```powershell
cd backend
python -m venv venv
```

### 2. Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

> If you get an execution-policy restriction error, run:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment

Copy `.env.example` to `.env` and configure your credentials:

```powershell
Copy-Item .env.example .env
```

Default configuration variables in `.env`:

```ini
APP_NAME=VulnScanner API
APP_VERSION=1.0.0
APP_ENV=development

API_HOST=127.0.0.1
API_PORT=8000

CORS_ORIGINS=http://localhost:5173

# PostgreSQL connection string (psycopg 3 driver)
DATABASE_URL=postgresql+psycopg://vulnscanner:changeme@localhost:5432/vulnscanner

# Required to save Jira, Slack, or Splunk credentials in PostgreSQL.
# Generate a value locally; never commit the generated key.
INTEGRATION_ENCRYPTION_KEY=

# Browser session cookie. Required for HTTPS production deployments.
SESSION_COOKIE_NAME=vulnscanner_session
SESSION_COOKIE_SECURE=false
```

> **Security Note:** Never commit `.env` with real credentials. `.env` is ignored by `.gitignore`.

---

## Database Migrations (Alembic)

VulnScanner uses Alembic alongside SQLAlchemy 2.x for schema versioning.

### Apply migrations to the database

Ensure your PostgreSQL instance is running, then run:

```powershell
alembic upgrade head
```

### Roll back the last migration

```powershell
alembic downgrade -1
```

### Inspect generated SQL offline (no live DB required)

```powershell
alembic upgrade head --sql
```

### Create a new migration revision

```powershell
alembic revision --autogenerate -m "describe_changes"
```

---

## Running the Development Server

Start Uvicorn with auto-reload:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The server binds to the loopback address above, but browser-facing URLs use
`localhost` to stay aligned with the Vite origin and Strict session cookies:

| Endpoint | Method | Description |
|---|---|---|
| `http://localhost:8000/` | GET | Root API greeting and doc link |
| `http://localhost:8000/api/v1/health` | GET | Basic application health check |
| `http://localhost:8000/api/v1/health/database` | GET | PostgreSQL connectivity check |
| `http://localhost:8000/api/v1/assets` | GET, POST | List (paginated/search) & create assets |
| `http://localhost:8000/api/v1/assets/{id}` | GET, PATCH, DELETE | Asset details, partial update, and safe deletion |
| `http://localhost:8000/api/v1/scans` | GET, POST | List scans (paginated/filters) & queue new scan |
| `http://localhost:8000/api/v1/scans/{id}` | GET | Scan details |
| `http://localhost:8000/api/v1/scans/{id}/cancel` | POST | Safely cancel a queued or running scan |
| `http://localhost:8000/api/v1/discoveries` | GET, POST | List or queue authorized CIDR/range host discovery |
| `http://localhost:8000/api/v1/discoveries/{id}` | GET | Discovery status, progress, and target metadata |
| `http://localhost:8000/api/v1/discoveries/{id}/hosts` | GET | Search and filter persisted discovered-host inventory |
| `http://localhost:8000/api/v1/discoveries/{id}/cancel` | POST | Cancel queued or running discovery |
| `http://localhost:8000/api/v1/vulnerabilities` | GET | List findings with severity, status, CVE, asset filters |
| `http://localhost:8000/api/v1/vulnerabilities/{id}` | GET, PATCH | Vulnerability details and triage status update |
| `http://localhost:8000/api/v1/dashboard` | GET | Aggregated counts, severity breakdown, and recent items |
| `http://localhost:8000/api/v1/settings` | GET, PATCH | Read and update database-managed platform preferences |
| `http://localhost:8000/api/v1/settings/integrations/{provider}` | PUT, DELETE | Replace or remove encrypted Jira, Slack, or Splunk credentials |
| `http://localhost:8000/api/v1/settings/api-key/regenerate` | POST | Replace the one-way platform API-key verifier |
| `http://localhost:8000/api/v1/settings/api-key` | DELETE | Remove the platform API-key verifier |
| `http://localhost:8000/api/v1/auth/session` | POST, GET, DELETE | Exchange an API key for, inspect, or revoke an HttpOnly operator session |
| `http://localhost:8000/docs` | GET | Swagger UI interactive documentation |
| `http://localhost:8000/redoc` | GET | ReDoc API documentation |

---

## Running Tests

### Phase 10 secret configuration

Generate the integration encryption key once per deployment:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the result as `INTEGRATION_ENCRYPTION_KEY` in the server environment. Keep it
separate from the database and back it up securely: changing or losing it makes
existing integration credentials unreadable. Integration secrets are encrypted
with Fernet before persistence. Platform API keys are stored only as salted
`scrypt` verifiers. Raw values are write-only and are not returned by the API.

Scanner concurrency and the rolling per-minute dispatch limit are applied to
real Nmap launches. If scans are already active, a changed concurrency limit is
deferred until the current queue drains. `NMAP_MAX_CONCURRENT` remains the safe
startup fallback before database-managed settings are loaded. Session timeout
and API-key authentication are enforced by the single-operator session layer
described below.

Authenticated operators can launch a scan in either of two authorization modes.
The default `allow_list` mode requires the target to match an enabled persistent
Authorized Target, including CIDR containment. The scan launcher uses
`on_demand` mode for one IP address or hostname and must send
`authorization_confirmed=true`, confirming that the operator owns the target or
has explicit permission to test it. On-demand CIDR ranges are rejected; register
reusable network scopes under Authorized Targets. Both modes retain target
normalization, fixed Nmap profiles, concurrency and rate limits, scan history,
failure handling, and cancellation. Nmap is always invoked with an argument list
and never through shell interpolation.

### Initial database administrator provisioning

Create the first username/password administrator locally after migrations:

```powershell
cd C:\Users\sai22\OneDrive\Documents\vuln\backend
python -m app.cli create-admin
```

The command interactively prompts for a full name, username, email, password,
password confirmation, and the explicit confirmation `CREATE`. Password entry
is hidden. The username, email, and password policy use the same validation as
normal registration, but the command assigns `role=admin` inside the trusted
local process. It stores only the existing Argon2id verifier, writes an audit
event, and never prints the plaintext password.

This is a one-time bootstrap command: it refuses duplicate usernames or emails
and, after one successful CLI-provisioned account, refuses to create another.
It can create a separate dedicated account without changing an administrator
that was previously authorized through another workflow. Create any further
administrators through an authenticated Admin Control Center workflow. Public
registration always assigns `role=user`; application startup and migrations
never create or promote an administrator automatically.

After creation, open `http://localhost:5173/login`, use **Administrator sign
in**, and enter the new username/email and password. Normal accounts continue
to use the standard sign-in form and receive HTTP 403 from administrator APIs.

To recover an existing administrator whose password is unavailable, run the
explicit local reset command:

```powershell
cd C:\Users\sai22\OneDrive\Documents\vuln\backend
python -m app.cli reset-admin-password --identifier database_admin
```

Type `RESET database_admin` when prompted, then enter the new password twice at
the hidden prompts. The command uses the existing password policy and Argon2id
hashing, revokes that account's sessions, writes an audit event without
credential material, and preserves its identity, role, and owned records.

### Initial API-key provisioning

All asset, scan, target, vulnerability, dashboard, report, and settings routes
require authentication. The root, health, and OpenAPI documentation endpoints
remain public. Scripts may send the
platform key in the `X-API-Key` header. The browser sends the key once to
`POST /api/v1/auth/session`, then uses an HttpOnly, SameSite=Strict cookie backed
by a server-side inactivity session. API keys and session tokens are never
accepted in URLs.

Create the first key locally from the backend directory after migrations:

```powershell
python -m app.cli provision-api-key
```

The command refuses to run if a key already exists and displays the new key only
once. Store it in an administrator password manager. It cannot be recovered from
the salted verifier. Subsequent regeneration and revocation require an already
authenticated request and revoke active browser sessions.

### Administrator account provisioning

The browser's ordinary administrator login accepts only the username/email and
password of an active database account whose role is already `admin`. Public
registration always creates a `user`; it never creates or promotes an
administrator.

If no administrator account exists, first register the intended account, then
provision the platform API key locally as described above. From a trusted local
PowerShell session, use the key directly against the protected admin API to find
and explicitly promote that account. `Read-Host` keeps the raw key out of command
history:

```powershell
$platformKey = Read-Host "Platform API key"
$adminHeaders = @{ "X-API-Key" = $platformKey }
$users = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/users?search=security-admin" -Headers $adminHeaders
$target = $users.items | Where-Object { $_.username -eq "security-admin" }

# Verify $target.id and $target.email before continuing.
$payload = @{ role = "admin"; version = $target.version } | ConvertTo-Json
Invoke-RestMethod -Method Patch -Uri "http://localhost:8000/api/v1/admin/users/$($target.id)" -Headers $adminHeaders -ContentType "application/json" -Body $payload
Remove-Variable platformKey, adminHeaders
```

Replace `security-admin` with the registered username. The protected update is
audited, revokes that account's existing sessions, and does not expose password
hashes or session tokens. The administrator can then use the credential form in
the browser. Keep the platform key in an administrator password manager for
restricted recovery, automation, or rotation; do not store it in browser local
storage or frontend environment variables.

### Lost-key administrative recovery

If the original key is lost and no valid browser session remains, use the local
administrator CLI from the `backend/` directory:

```powershell
python -m app.cli rotate-api-key
```

The command requires the explicit confirmation `ROTATE` and warns that the old
key will stop working and all existing operator sessions will be revoked. It
generates the replacement in memory, updates the existing salted verifier and
revokes sessions in one database transaction, then prints the raw replacement
key exactly once after a successful commit. The key is never accepted as a
command argument or environment variable and cannot be retrieved later.

Use the replacement only from a trusted administrative client through the
`X-API-Key` header; the browser login page intentionally has no API-key field.
Confirm that the previous key and old sessions no longer work. If the command
fails or confirmation is declined, no usable replacement key is displayed. Do
not use direct database deletion or unauthenticated HTTP requests as a recovery
method.

Session inactivity uses the database-managed timeout from the Settings page.
Each authenticated request advances the server-side expiry; expired or revoked
sessions receive HTTP 401. Set `SESSION_COOKIE_SECURE=true` for HTTPS deployments.
When `APP_ENV=production`, the API refuses to start unless secure cookies are
enabled. Configure `CORS_ORIGINS` with the exact browser origin(s) used by the
deployed frontend; credentialed requests cannot use a wildcard origin.

All unit tests are isolated and **do not require a running PostgreSQL instance** (using an in-memory SQLite test database for API and query verification):

```powershell
pytest -v
```

To run a specific test suite:

```powershell
# Run REST API integration tests (Phase 3)
pytest tests/test_api.py -v

# Run database model and schema validation tests (Phase 2)
pytest tests/test_database.py -v

# Run health check tests (Phase 1)
pytest tests/test_health.py -v
```

---

## Project Structure

```
backend/
├── alembic/
│   ├── versions/
│   │   └── 0ec56e5f40b3_initial_models_asset_scan_vulnerability.py
│   ├── env.py                 # Reads app DATABASE_URL & model metadata
│   └── script.py.mako
├── alembic.ini                # Alembic CLI configuration
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI application factory & router registration
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py          # Settings with DATABASE_URL & CORS
│   ├── db/
│   │   ├── __init__.py
│   │   ├── base.py            # SQLAlchemy DeclarativeBase
│   │   └── session.py         # Lazy engine, sessionmaker & get_db dependency
│   ├── models/
│   │   ├── __init__.py        # ORM model registry
│   │   ├── asset.py           # Asset ORM model
│   │   ├── scan.py            # Scan ORM model
│   │   └── vulnerability.py   # Vulnerability ORM model
│   ├── schemas/
│   │   ├── __init__.py        # Pydantic v2 schemas registry
│   │   ├── asset.py
│   │   ├── common.py          # PaginatedResponse generic schema
│   │   ├── dashboard.py       # DashboardResponse and SeverityCounts
│   │   ├── scan.py
│   │   └── vulnerability.py
│   └── api/
│       ├── __init__.py
│       └── routes/
│           ├── __init__.py
│           ├── assets.py      # /assets CRUD endpoints
│           ├── dashboard.py   # /dashboard telemetry
│           ├── health.py      # /health & /health/database
│           ├── scans.py       # /scans queue & cancel
│           └── vulnerabilities.py # /vulnerabilities filters
├── tests/
│   ├── test_api.py            # Phase 3 REST API & CRUD tests (in-memory SQLite)
│   ├── test_database.py       # Phase 2 model & schema constraint tests
│   └── test_health.py         # Phase 1 health check tests
├── .env.example               # Safe template with placeholder database URL
├── .gitignore
├── requirements.txt           # Dependencies
└── README.md
```
