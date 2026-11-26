# VulnScan — SOC Vulnerability Scanner Dashboard

A production-grade, dark-mode Security Operations Center (SOC) vulnerability management and scanning orchestration dashboard built with **React 19**, **TypeScript**, and **Vite**.

Designed with a high-density, professional SOC aesthetic — focused on clarity, telemetry visualization, rapid incident triage, and zero visual clutter.

---

## 🛡️ Key Features & Capabilities

- **Live Telemetry Dashboard (`/`)**: Real-time security posture score, severity breakdown gauge, vulnerability discovery trends over time (Recharts), active scan status feeds, and an on-demand PDF snapshot generated from the latest successful backend telemetry. Dashboard snapshots are local downloads and are not persisted security reports.
- **Scan Engine Orchestration (`/scans`)**: Grid and tabular view of security scans, live progress indicators, explicitly confirmed single-IP/hostname on-demand scans, persistent Authorized Target scopes, fixed Nmap profiles, and lifecycle management (Stop, Delete).
- **Network Discovery (`/discovery`)**: Explicitly authorized IPv4/IPv6 CIDR and inclusive IP-range host discovery, bounded to 4,096 addresses by default, with searchable host inventory, MAC/vendor details when Nmap supplies them, cancellation, and deliberate per-host scan actions.
- **Vulnerability Investigation Drawer (`/vulnerabilities`)**: High-impact CVSS 3.1 scoring, status triage (Open, In Progress, Resolved, False Positive), asset linkage, PoC evidence blocks, and step-by-step remediation guidance.
- **Asset Inventory & Classification (`/targets`)**: Categorized by Server, Workstation, Network Device, Web Application, and Cloud Asset. Criticality metrics, IP/FQDN tracking, and Asset inspection drawer.
- **Security Reports (`/reports`)**: Saved aggregate report history with the existing PDF/CSV exports, plus authenticated scan-specific reports at `/reports/:scanId`. Scan reports use `GET /api/v1/reports/scans/{scan_id}` as the shared source for the in-app viewer and one-click PDF, including persisted target, ports, services, and linked vulnerability findings.
- **Persistent Accounts (`/register`, `/login`)**: PostgreSQL-backed registration and Argon2id password login. Browser authentication uses revocable HttpOnly sessions plus a SameSite double-submit CSRF token. Explicitly authorized administrators use the same credential flow through the role-enforcing administrator sign-in; platform API keys remain a non-browser bootstrap and recovery mechanism.
- **SOC Platform Settings (`/settings`)**: Configurable scanner concurrency/rate-limiting, webhook and SIEM integrations (Jira, Slack, Splunk), API key regeneration, session timeout controls, and dark-mode theme accenting.
- **Design System Showcase (`/design-system`)**: Complete interactive catalog of UI tokens, badges with radar ping ripples, alert banners, modal dialogues, drawers, and form controls.

---

## 🏗️ Architecture & Decoupled API Pattern

The application uses an authenticated **API Service Abstraction**. Production pages read and mutate persisted PostgreSQL data through the FastAPI backend; deterministic mock fixtures are retained only for isolated tests.

```text
React Pages / Components
         │
         ▼
  src/services/api.ts (Authenticated HTTP API client)
         │
         ▼
  FastAPI + PostgreSQL REST Endpoints
         ▲
  src/__tests__/fixtures/mockData.ts (test-only fixtures)
```

The client centralizes authenticated `fetch()` behavior, typed response mapping, server validation errors, 204 responses, query encoding, and abort-signal propagation. The TypeScript interfaces defined in [`src/types/index.ts`](src/types/index.ts) map to the FastAPI Pydantic schemas.

---

## 🎨 Design System & SOC Aesthetic

- **Theme**: Pure SOC Dark Mode (`#0b0f17` background, `#111827` cards, `#1f2937` borders).
- **Typography**: Google Inter for UI, JetBrains Mono for CVEs, IP addresses, hashes, and terminal logs.
- **Severity Color Tokens**:
  - **Critical**: `#ef4444` (CVSS 9.0–10.0)
  - **High**: `#f97316` (CVSS 7.0–8.9)
  - **Medium**: `#f59e0b` (CVSS 4.0–6.9)
  - **Low**: `#3b82f6` (CVSS 0.1–3.9)
  - **Info**: `#64748b` (CVSS 0.0)
- **Micro-Interactions**: Radar pulse ping animations on running scans, smooth 280ms cubic-bezier drawer transitions, hover-lift card elevations, and sheen reflections on interactive buttons.

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ or 20+
- npm 9+ or pnpm
- Python 3.11+
- PostgreSQL with the database configured in `backend/.env`

### Installation

```bash
git clone <repo-url> vuln
cd vuln
npm install
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env # skip this when backend/.env is already configured
alembic upgrade head
cd ..
```

### Running the Local Application

Activate the backend virtual environment, then start both FastAPI and Vite from
the repository root:

```powershell
.\backend\venv\Scripts\Activate.ps1
npm run dev
```

`npm run dev` starts FastAPI on `127.0.0.1:8000` and Vite on
`http://localhost:5173/`. Browser API requests deliberately use
`http://localhost:8000/api/v1`; keep the browser-facing hostname as `localhost`
so the Strict session cookie remains same-site. Verify startup with
`http://localhost:8000/api/v1/health`. Use `npm run dev:api` or
`npm run dev:web` only when intentionally running one service by itself.

### Running Automated Test Suite

```bash
npm test
```
Runs the complete deterministic frontend suite with Vitest. Service-only tests run in Node, while hook and component tests opt into jsdom and React Testing Library. Real network requests are blocked by the shared test setup.

```bash
npm run test:watch
npm run test:coverage
```

The coverage command measures the critical API service, PDF export, async hook, shared scan context, and scan-activity utility without imposing an arbitrary threshold. Backend tests remain on pytest and are run separately from `backend/`.

### Building for Production

```bash
npm run build
```
Executes TypeScript compilation (`tsc -b`) and Vite production bundle optimization with vendor chunk splitting (`dist/`).

For a deployed frontend, set `VITE_API_BASE_URL` to the HTTPS API origin and path
before building (for example, `https://api.example.com/api/v1`). Vite embeds this
value in the browser bundle at build time; do not put API keys or other secrets in
frontend environment variables. The default `.env.example` value is for local
development only.

### Backend deployment requirements

From `backend/`, copy `.env.example` to `.env`, configure PostgreSQL, and apply
the Alembic migrations before starting the API. Configure `CORS_ORIGINS` with the
exact frontend origin(s), including scheme and port where applicable. The first
platform API key is provisioned locally with `python -m app.cli provision-api-key`
after migrations; the command displays the raw key only once.

If the existing key is lost and no authenticated browser session remains, run
the local administrative recovery command from `backend/`:

```powershell
python -m app.cli rotate-api-key
```

The command requires typing `ROTATE` after warning that the old key will stop
working and all operator sessions will be revoked. It generates a replacement
inside the CLI, atomically replaces the verifier, and displays the raw key once
only after commit. Copy it directly into the authentication screen; it cannot
be retrieved later. This is intentionally not exposed as an unauthenticated API
operation.

For HTTPS deployments set `SESSION_COOKIE_SECURE=true` and keep the frontend and
API origins aligned with the reverse proxy. The backend rejects production
startup when `APP_ENV=production` is used without secure session cookies. Before starting
this version, apply the non-destructive account/ownership migration from `backend/`:

```powershell
alembic upgrade head
```

Existing assets, scans, reports, and authorized targets remain unowned legacy
records and are visible only to the API-key administrator. Newly registered
users see only resources created by their own authenticated account.
Keep `INTEGRATION_ENCRYPTION_KEY`, `DATABASE_URL`, and any deployment credentials in
the server environment only. A reverse proxy must forward HTTPS, cookies, and
the configured CORS origin correctly. Local test suites use isolated fixtures;
they do not verify a deployed reverse-proxy or PostgreSQL environment.

### Admin Control Center

Apply the latest additive database migration before using the control center:

```powershell
cd backend
.\venv\Scripts\alembic.exe upgrade head
```

Sign in through **Administrator access** with an existing active administrator's
username or email and password, then open `/admin`. Public registration creates
a standard user and cannot grant administrative access. The control center
provides global overview metrics, user and session
management, scan operations, persisted reports, discoveries, confirmed
vulnerabilities, and append-only audit history.

If no database administrator exists, create the first dedicated administrator
through the trusted local interactive command:

```powershell
cd C:\Users\sai22\OneDrive\Documents\vuln\backend
python -m app.cli create-admin
```

The command uses the existing registration validation and Argon2id password
hashing, requires the explicit confirmation `CREATE`, records an audit event,
and can be successfully used only once. It creates a distinct account without
changing any existing administrator and never prints the password. Public
registration remains standard-user-only. The platform API key
is not entered into the browser login page; its protected API workflow and the
confirmed `python -m app.cli rotate-api-key` command remain available for
restricted recovery and automation.

If the original password is unavailable, reset one existing administrator
through the explicit local recovery command:

```powershell
cd C:\Users\sai22\OneDrive\Documents\vuln\backend
python -m app.cli reset-admin-password --identifier database_admin
```

Type `RESET database_admin` when prompted, then enter the new password twice at
the hidden prompts. The command validates and hashes it with the existing
Argon2id implementation, revokes that account's sessions, records a
credential-free audit event, and preserves the account and owned data.

Password recovery is an administrator-supplied temporary credential workflow;
there is no email-delivery integration. The server stores only its hash,
revokes the user's existing sessions, and requires the user to replace it at
the next login. Completing that change revokes the temporary session and
requires a fresh sign-in. Communicate temporary credentials through an
appropriate out-of-band secure channel.

Permanent account deletion is intentionally unavailable. Disable an account to
block access while preserving its scan, report, session, ownership, and audit
history. Online status means that an unrevoked, unexpired server session exists;
it is not instantaneous WebSocket presence. No additional environment settings
are required beyond the existing authentication, cookie, CORS, PostgreSQL, and
scanner configuration.

---

## 📁 Project Structure

```text
vuln/
├── public/                 # Static assets, SVG icons, favicon
├── src/
│   ├── __tests__/          # Vitest automated test suites
│   ├── assets/             # Brand logos and iconography
│   ├── components/
│   │   ├── dashboard/      # Domain widgets: AssetDrawer, VulnDrawer, PostureGauge, StatCards
│   │   └── ui/             # Core design system: Badge, Button, Modal, Drawer, Toast, Skeleton
│   ├── data/
│   │   └── __tests__/fixtures/mockData.ts # Test-only fixtures
│   ├── hooks/              # Custom React hooks (useLocalStorage, useDebounce, etc.)
│   ├── layouts/            # AppShell, TopNavbar, Sidebar navigation
│   ├── pages/              # Primary route views (Dashboard, Scans, Vulns, Assets, Reports, Settings)
│   ├── services/
│   │   └── api.ts          # Unified API service layer
│   ├── store/
│   │   └── ScanContext.tsx # Global state provider for scans and telemetry
│   ├── types/
│   │   └── index.ts        # TypeScript contracts & SOC domain interfaces
│   ├── App.tsx             # Root routing and context provider wrapper
│   ├── index.css           # Global tokens, reset, typography, and utility classes
│   └── main.tsx            # Application entry point
├── package.json            # Scripts and dependencies
├── tsconfig.json           # Strict TypeScript configuration
└── vite.config.ts          # Vite build config with vendor chunk optimization
```

---

## 📜 Roadmap Completion Summary

- [x] **Phase 1**: Architecture & Setup
- [x] **Phase 2**: Design Tokens & Dark Theme
- [x] **Phase 3**: Core UI Components
- [x] **Phase 4**: AppShell Layout
- [x] **Phase 5**: Dashboard Telemetry & Posture
- [x] **Phase 6**: Scan Engine Management & Terminal Logs
- [x] **Phase 7**: Asset Management & Drawer
- [x] **Phase 8**: Vulnerability Investigation & CVSS Triage
- [x] **Phase 9**: Security Reports & Export Simulation
- [x] **Phase 10**: Platform Settings & API Keys
- [x] **Phase 11**: Global Scan State & Telemetry Sync
- [x] **Phase 12**: Mock API Service Layer
- [x] **Phase 13**: UX States (Loading Skeletons, Error Boundary, Filter Resets)
- [x] **Phase 13.1**: Real Dashboard PDF Export
- [x] **Phase 14**: Micro-interactions & Radar Ping Animations
- [x] **Phase 15**: Vitest Automated Testing (207/207 passing)
- [x] **Phase 16**: Final Polish, Vendor Chunking & Production Verification
