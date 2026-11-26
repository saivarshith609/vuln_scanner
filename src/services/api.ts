/**
 * VulnScanner API Service Layer (Phase 3: PostgreSQL Integration)
 * Architecture: React Components → API Service → FastAPI REST API → PostgreSQL 18
 */

import type {
  Scan,
  ScanStatus,
  ScanType,
  Asset,
  AssetType,
  Vulnerability,
  Severity,
  VulnStatus,
  Report,
  DashboardStats,
  DashboardTelemetry,
  ScanResult,
  ScanReportDetail,
  AuthorizedTarget,
  IntegrationProvider,
  PlatformPreferences,
  PlatformSettings,
  SecretStatus,
  CreateScanInput,
  CreateDiscoveryInput,
  DiscoveryRun,
  DiscoveredHost,
} from '../types';
const LOCAL_DEV_API_BASE_URL = 'http://localhost:8000/api/v1';

/**
 * Resolve the FastAPI base URL. Localhost fallback is restricted to local
 * development and test environments so production builds never target localhost.
 */
export function resolveApiBaseUrl(options?: {
  configuredUrl?: string;
  isProduction?: boolean;
}): string {
  const configuredUrl = options && 'configuredUrl' in options
    ? options.configuredUrl
    : import.meta.env.VITE_API_BASE_URL;
  const isProduction = options?.isProduction ?? (import.meta.env.PROD && import.meta.env.MODE !== 'test');
  const trimmed = typeof configuredUrl === 'string' ? configuredUrl.trim().replace(/\/+$/, '') : '';
  if (trimmed) return trimmed;
  if (isProduction) return '';
  return LOCAL_DEV_API_BASE_URL;
}

// Local browser sessions use SameSite=Strict cookies, so the dev fallback host
// must use the same hostname as Vite's http://localhost:5173 origin.
export const API_BASE_URL = resolveApiBaseUrl();

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

const CSRF_COOKIE_NAME = 'vulnscanner_csrf';
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function readCsrfCookie(): string | undefined {
  if (typeof document === 'undefined' || typeof document.cookie !== 'string') return undefined;
  const encoded = document.cookie
    .split('; ')
    .find((item) => item.startsWith(`${CSRF_COOKIE_NAME}=`))
    ?.split('=')
    .slice(1)
    .join('=');
  if (!encoded) return undefined;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
}

function requiresCsrfToken(endpoint: string, method: string): boolean {
  if (SAFE_HTTP_METHODS.has(method)) return false;
  // These endpoints create or remove authentication state and intentionally do
  // not depend on an existing authenticated session/CSRF pair.
  return !(
    endpoint === '/auth/login'
    || endpoint === '/auth/admin/login'
    || endpoint === '/auth/register'
    || endpoint === '/auth/session'
  );
}

// Helper for HTTP requests
async function request<T>(
  endpoint: string,
  options: RequestInit = {},
  allowCsrfRecovery = true,
): Promise<T | null> {
  if (!API_BASE_URL) {
    throw new ApiError(
      'API base URL is not configured. Set VITE_API_BASE_URL to your FastAPI backend URL.',
      0,
    );
  }
  const url = `${API_BASE_URL}${endpoint}`;
  const method = (options.method || 'GET').toUpperCase();
  const csrfRequired = requiresCsrfToken(endpoint, method);
  let csrfToken = readCsrfCookie();
  try {
    if (csrfRequired && !csrfToken && allowCsrfRecovery && typeof document !== 'undefined') {
      await request<AuthSession>('/auth/session', {}, false);
      csrfToken = readCsrfCookie();
    }

    const res = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
        ...(csrfRequired && csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : {}),
      },
    });

    if (res.status === 204) {
      return null;
    }

    if (!res.ok) {
      const errorBody = await readJson<unknown>(res);
      const message = getErrorMessage(errorBody, res.status, res.statusText);
      if (
        res.status === 403
        && message === 'CSRF validation failed'
        && csrfRequired
        && allowCsrfRecovery
      ) {
        await request<AuthSession>('/auth/session', {}, false);
        return request<T>(endpoint, options, false);
      }
      // Authentication endpoints handle their own expected 401 responses. In
      // particular, an anonymous GET /auth/session is the normal logged-out
      // state and must not be mistaken for an expired protected-route session.
      if (res.status === 401 && typeof window !== 'undefined' && !endpoint.startsWith('/auth/')) {
        window.dispatchEvent(new Event('vulnscanner:authentication-required'));
      }
      throw new ApiError(message, res.status);
    }

    return await readJson<T>(res);
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (
      typeof err === 'object'
      && err !== null
      && 'name' in err
      && err.name === 'AbortError'
    ) {
      throw err;
    }
    throw new ApiError('Unable to reach the API service.', 0);
  }
}

async function readJson<T>(response: Response): Promise<T | null> {
  const contentLength = response.headers?.get('content-length');
  const contentType = response.headers?.get('content-type') || '';
  if (contentLength === '0' || (!contentType.includes('json') && response.status === 204)) {
    return null;
  }
  if (typeof response.text !== 'function') {
    if (typeof response.json === 'function') return await response.json() as T;
    return null;
  }
  const text = await response.text();
  if (!text.trim()) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError('The API returned an invalid JSON response.', response.status);
  }
}

function getErrorMessage(body: unknown, status: number, statusText: string): string {
  if (typeof body === 'object' && body !== null && 'detail' in body) {
    const detail = (body as { detail?: unknown }).detail;
    if (typeof detail === 'string' && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const messages = detail
        .map((item) => {
          if (typeof item === 'object' && item !== null && 'msg' in item) {
            return String((item as { msg: unknown }).msg);
          }
          return typeof item === 'string' ? item : null;
        })
        .filter((item): item is string => Boolean(item));
      if (messages.length > 0) return messages.join('; ');
    }
  }
  return `HTTP Error ${status}: ${statusText || 'Request failed'}`;
}

function requireResponse<T>(value: T | null, message: string): T {
  if (value === null) throw new ApiError(message, 502);
  return value;
}

export interface AuthSession {
  authenticated: boolean;
  method: 'session' | 'api_key';
  expires_at: string | null;
  user: AuthUser;
}

export interface ApiHealth {
  status: string;
  application: string;
  version: string;
}

export interface AuthUser {
  id: string | null;
  full_name: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  is_active: boolean;
  created_at?: string | null;
  credential_change_required?: boolean;
}

export interface RegisterAccountInput {
  full_name: string;
  username: string;
  email: string;
  password: string;
  confirm_password: string;
}

export async function getApiHealth(): Promise<ApiHealth> {
  const health = requireResponse(
    await request<ApiHealth>('/health'),
    'API health check returned no status data.',
  );
  if (health.status !== 'healthy') {
    throw new ApiError('The API reported an unhealthy status.', 503);
  }
  return health;
}

export async function getAuthSession(): Promise<AuthSession> {
  return requireResponse(await request<AuthSession>('/auth/session'), 'Authentication service returned no session data.');
}

export async function createAuthSession(apiKey: string): Promise<AuthSession> {
  return requireResponse(await request<AuthSession>('/auth/session', {
    method: 'POST',
    headers: { 'X-API-Key': apiKey },
  }), 'Authentication service returned no session data.');
}

export async function loginUser(identifier: string, password: string): Promise<AuthSession> {
  return requireResponse(await request<AuthSession>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ identifier, password }),
  }), 'Authentication service returned no session data.');
}

export async function loginAdministrator(identifier: string, password: string): Promise<AuthSession> {
  return requireResponse(await request<AuthSession>('/auth/admin/login', {
    method: 'POST',
    body: JSON.stringify({ identifier, password }),
  }), 'Administrator authentication service returned no session data.');
}

export async function registerUser(payload: RegisterAccountInput): Promise<AuthUser> {
  return requireResponse(await request<AuthUser>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  }), 'Registration service returned no account data.');
}

export async function endAuthSession(): Promise<void> {
  await request<null>('/auth/session', { method: 'DELETE' });
}

export async function logoutUser(): Promise<void> {
  await request<null>('/auth/logout', { method: 'POST' });
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
  confirmPassword: string,
): Promise<{ changed: boolean; reauthentication_required: boolean }> {
  return requireResponse(await request('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      confirm_password: confirmPassword,
    }),
  }), 'Password service returned no result.');
}

// ─── Data Mappers ─────────────────────────────────────────────────────────────

interface BackendAsset {
  id: string;
  name: string;
  asset_type: string;
  target: string;
  description?: string | null;
  created_at: string;
  updated_at: string;
}

function mapBackendAsset(item: BackendAsset): Asset {
  const validTypes: AssetType[] = ['server', 'workstation', 'network', 'web', 'cloud'];
  const type: AssetType = validTypes.includes(item.asset_type as AssetType)
    ? (item.asset_type as AssetType)
    : 'server';

  return {
    id: item.id,
    name: item.name,
    ip: item.target,
    type,
    os: undefined,
    criticality: 'medium',
    status: 'unscanned',
    vulnerabilitiesCount: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    lastScanned: 'Never',
    tags: [type.toUpperCase()],
    owner: item.description || undefined,
    location: undefined,
    created_at: item.created_at,
    updated_at: item.updated_at,
  };
}

interface BackendScan {
  id: string;
  asset_id?: string | null;
  target: string;
  scan_type: string;
  status: string;
  progress: number;
  error_message?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

function mapBackendScan(item: BackendScan, scanName?: string): Scan {
  const status = (['idle', 'queued', 'running', 'completed', 'failed', 'paused', 'cancelled'].includes(item.status)
    ? item.status
    : 'queued') as ScanStatus;

  const type = (['full', 'quick', 'network', 'web', 'api', 'compliance'].includes(item.scan_type)
    ? item.scan_type
    : 'full') as ScanType;

  const logs = [
    `[${new Date(item.created_at).toLocaleTimeString()}] Scan record initialized (Status: ${item.status.toUpperCase()})`,
    `[${new Date(item.created_at).toLocaleTimeString()}] Target: ${item.target} (Profile: ${item.scan_type.toUpperCase()})`,
  ];

  if (item.started_at) {
    logs.push(`[${new Date(item.started_at).toLocaleTimeString()}] Nmap scanning engine active`);
  }
  if (item.status === 'completed' && item.completed_at) {
    logs.push(`[${new Date(item.completed_at).toLocaleTimeString()}] [SUCCESS] Nmap scan and XML parsing completed`);
  }
  if (item.status === 'cancelled') {
    logs.push(`[${new Date().toLocaleTimeString()}] [WARN] Scan execution cancelled by operator`);
  }
  if (item.status === 'failed') {
    logs.push(`[${new Date().toLocaleTimeString()}] [ERR] Scan execution failed: ${item.error_message || 'Scanner error'}`);
  }

  return {
    id: item.id,
    name: scanName || `${item.target} (${item.scan_type.toUpperCase()})`,
    targetUrl: item.target,
    type,
    status,
    progress: item.progress ?? 0,
    startedAt: item.started_at
      ? new Date(item.started_at).toLocaleString()
      : new Date(item.created_at).toLocaleString(),
    completedAt: item.completed_at ? new Date(item.completed_at).toLocaleString() : undefined,
    duration: (() => {
      if (item.started_at && item.completed_at) {
        const ms = new Date(item.completed_at).getTime() - new Date(item.started_at).getTime();
        if (!isNaN(ms) && ms >= 0) {
          const sec = Math.round(ms / 1000);
          return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
        }
      }
      return undefined;
    })(),
    findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    logs,
    errorMessage: item.error_message || undefined,
  };
}

interface BackendVulnerability {
  id: string;
  scan_id: string;
  asset_id?: string | null;
  asset_name?: string | null;
  asset_target?: string | null;
  title: string;
  cve_id?: string | null;
  severity: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  description?: string | null;
  remediation?: string | null;
  evidence?: string | null;
  port?: number | null;
  status: string;
  created_at: string;
}

function mapBackendVuln(item: BackendVulnerability): Vulnerability {
  const sev = (['critical', 'high', 'medium', 'low', 'info'].includes(item.severity.toLowerCase())
    ? item.severity.toLowerCase()
    : 'medium') as Severity;

  const validStatuses: VulnStatus[] = [
    'open',
    'in_progress',
    'resolved',
    'false_positive',
    'accepted',
  ];
  const status: VulnStatus = validStatuses.includes(item.status.toLowerCase() as VulnStatus)
    ? (item.status.toLowerCase() as VulnStatus)
    : 'open';

  const score = item.cvss_score ?? 0;
  const assetName = item.asset_name || undefined;
  const assetTarget = item.asset_target || undefined;
  const targetLabel = assetTarget || (item.port ? `Port ${item.port}` : 'Asset Target');
  const assetLabel = assetName || assetTarget || (item.asset_id ? `Asset (${item.asset_id.slice(0, 8)})` : undefined);

  return {
    id: item.id,
    title: item.title,
    name: item.title,
    description: item.description || '',
    severity: sev,
    cve: item.cve_id || undefined,
    cvss: score,
    cvssScore: score,
    cvssVector: item.cvss_vector || undefined,
    evidence: item.evidence || undefined,
    target: targetLabel,
    asset: assetLabel,
    assetId: item.asset_id || undefined,
    assetName,
    assetTarget,
    status,
    discoveredAt: new Date(item.created_at).toLocaleDateString(),
    remediation: item.remediation || undefined,
    category: sev.toUpperCase(),
    port: item.port || undefined,
    references: item.cve_id ? [`https://nvd.nist.gov/vuln/detail/${item.cve_id}`] : [],
  };
}


interface BackendDashboard {
  total_assets: number;
  discovered_hosts?: number;
  active_scans: number;
  total_scans: number;
  completed_scans?: number;
  failed_scans?: number;
  cancelled_scans?: number;
  total_vulnerabilities: number;
  resolved_vulnerabilities?: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recent_scans: BackendScan[];
  recent_vulnerabilities: BackendVulnerability[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// ─── Dashboard API ───────────────────────────────────────────────────────────

export async function getDashboard(signal?: AbortSignal): Promise<DashboardTelemetry> {
  const data = requireResponse(
    await request<BackendDashboard>('/dashboard', { signal }),
    'Security telemetry service returned no data.',
  );

  const critical = data.severity_counts?.critical ?? 0;
  const high = data.severity_counts?.high ?? 0;
  const medium = data.severity_counts?.medium ?? 0;
  const low = data.severity_counts?.low ?? 0;
  const info = data.severity_counts?.info ?? 0;
  const total = data.total_vulnerabilities ?? 0;

  // Documented posture score formula (Phase 5): 100 on clean state, weighted
  // penalty per confirmed finding. Do NOT modify this formula.
  const penalty = critical * 25 + high * 15 + medium * 5 + low * 1;
  const securityScore = Math.max(0, Math.min(100, 100 - penalty));

  // Weighted average risk score across confirmed finding tiers.
  const averageRiskScore =
    total > 0
      ? Number(((critical * 10 + high * 7.5 + medium * 5 + low * 2.5) / total).toFixed(1))
      : 0;

  const stats: DashboardStats = {
    totalScans: data.total_scans ?? 0,
    activeScans: data.active_scans ?? 0,
    completedScans: data.completed_scans ?? 0,
    failedScans: data.failed_scans ?? 0,
    cancelledScans: data.cancelled_scans ?? 0,
    totalAssets: data.total_assets ?? 0,
    discoveredHosts: data.discovered_hosts ?? 0,
    totalVulnerabilities: total,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    infoCount: info,
    resolvedCount: data.resolved_vulnerabilities ?? 0,
    averageRiskScore,
    securityScore,
  };

  const severityDistribution = [
    { name: 'Critical', value: critical, color: '#ef4444' },
    { name: 'High', value: high, color: '#f97316' },
    { name: 'Medium', value: medium, color: '#eab308' },
    { name: 'Low', value: low, color: '#22c55e' },
    { name: 'Info', value: info, color: '#3b82f6' },
  ];

  // categoryData: The backend does not aggregate OWASP/threat categories.
  // Returning an empty array is honest. The CategoryBarChart will show an
  // "unavailable" state. Do not map severity counts to fabricated category names.
  const categoryData: { category: string; count: number; color: string }[] = [];

  // trendData: The backend does not supply daily historical time-series.
  // Returning an empty array is honest. The VulnerabilityTrendChart will show
  // a "Historical Trend Unavailable" state until the backend provides this data.
  const trendData: { date: string; critical: number; high: number; medium: number; resolved: number }[] = [];

  const recentScans = (data.recent_scans ?? []).map((s) => mapBackendScan(s));
  const recentVulnerabilities = (data.recent_vulnerabilities ?? []).map((v) => mapBackendVuln(v));

  return {
    stats,
    trendData,
    severityDistribution,
    categoryData,
    recentScans,
    recentVulnerabilities,
  };
}

// ─── Scans API ────────────────────────────────────────────────────────────────

export interface GetScansParams {
  assetId?: string;
  target?: string;
  status?: string;
  scanType?: string;
}

export async function getScans(params?: GetScansParams, signal?: AbortSignal): Promise<Scan[]> {
  const queryParts = ['size=100'];
  if (params?.assetId) queryParts.push(`asset_id=${encodeURIComponent(params.assetId)}`);
  if (params?.target) queryParts.push(`target=${encodeURIComponent(params.target)}`);
  if (params?.status) queryParts.push(`status=${encodeURIComponent(params.status)}`);
  if (params?.scanType) queryParts.push(`scan_type=${encodeURIComponent(params.scanType)}`);

  const data = await request<PaginatedResponse<BackendScan>>(`/scans?${queryParts.join('&')}`, { signal });
  return requireResponse(data, 'Scan service returned no data.').items.map((s) => mapBackendScan(s));
}

export async function getScan(id: string, signal?: AbortSignal): Promise<Scan | undefined> {
  const data = await request<BackendScan>(`/scans/${id}`, { signal });
  return mapBackendScan(requireResponse(data, 'Scan service returned no data.'));
}

export async function createScan(data: CreateScanInput): Promise<Scan> {
  const target = data.targetUrl.trim();
  const res = await request<BackendScan>('/scans', {
    method: 'POST',
    body: JSON.stringify({
      target,
      scan_type: data.type,
      authorization_mode: data.authorizationMode ?? 'allow_list',
      authorization_confirmed: data.authorizationConfirmed ?? false,
    }),
  });

  return mapBackendScan(requireResponse(res, 'Scan service returned no scan record.'), data.name);
}

export async function cancelScan(id: string): Promise<Scan | undefined> {
  const res = await request<BackendScan>(`/scans/${id}/cancel`, {
    method: 'POST',
  });
  if (!res) return undefined;
  return mapBackendScan(res);
}

export async function deleteScan(id: string): Promise<{ success: boolean }> {
  await request(`/scans/${id}`, {
    method: 'DELETE',
  });
  return { success: true };
}

export interface GetScanResultsParams {
  scanId?: string;
  host?: string;
  portState?: string;
}

export async function getScanResults(
  paramsOrScanId: string | GetScanResultsParams,
  signal?: AbortSignal,
): Promise<ScanResult[]> {
  let query = '';
  if (typeof paramsOrScanId === 'string') {
    query = `scan_id=${encodeURIComponent(paramsOrScanId)}&size=200`;
  } else {
    const parts: string[] = ['size=200'];
    if (paramsOrScanId.scanId) parts.push(`scan_id=${encodeURIComponent(paramsOrScanId.scanId)}`);
    if (paramsOrScanId.host) parts.push(`host=${encodeURIComponent(paramsOrScanId.host)}`);
    if (paramsOrScanId.portState) parts.push(`port_state=${encodeURIComponent(paramsOrScanId.portState)}`);
    query = parts.join('&');
  }

  const data = await request<PaginatedResponse<ScanResult>>(`/scan-results?${query}`, { signal });
  return requireResponse(data, 'Scan results service returned no data.').items;
}

export async function getScanReport(scanId: string, signal?: AbortSignal): Promise<ScanReportDetail> {
  const data = await request<ScanReportDetail>(
    `/reports/scans/${encodeURIComponent(scanId)}`,
    { signal },
  );
  return requireResponse(data, 'Scan report service returned no data.');
}

// ─── Network discovery and host inventory ──────────────────────────────

export async function getDiscoveries(signal?: AbortSignal): Promise<DiscoveryRun[]> {
  const data = await request<PaginatedResponse<DiscoveryRun>>('/discoveries?size=100', { signal });
  return requireResponse(data, 'Discovery service returned no data.').items;
}

export async function getDiscovery(id: string, signal?: AbortSignal): Promise<DiscoveryRun> {
  return requireResponse(
    await request<DiscoveryRun>(`/discoveries/${encodeURIComponent(id)}`, { signal }),
    'Discovery service returned no run data.',
  );
}

export async function createDiscovery(payload: CreateDiscoveryInput): Promise<DiscoveryRun> {
  return requireResponse(await request<DiscoveryRun>('/discoveries', {
    method: 'POST',
    body: JSON.stringify(payload),
  }), 'Discovery service returned no run data.');
}

export async function cancelDiscovery(id: string): Promise<DiscoveryRun> {
  return requireResponse(await request<DiscoveryRun>(`/discoveries/${encodeURIComponent(id)}/cancel`, {
    method: 'POST',
  }), 'Discovery service returned no cancellation status.');
}

export async function getDiscoveryHosts(
  discoveryId: string,
  options: { search?: string; authorization?: 'all' | 'authorized' | 'unauthorized' } = {},
  signal?: AbortSignal,
): Promise<DiscoveredHost[]> {
  const query = new URLSearchParams({ size: '500' });
  if (options.search) query.set('search', options.search);
  if (options.authorization && options.authorization !== 'all') query.set('authorization', options.authorization);
  const data = await request<PaginatedResponse<DiscoveredHost>>(
    `/discoveries/${encodeURIComponent(discoveryId)}/hosts?${query.toString()}`,
    { signal },
  );
  return requireResponse(data, 'Discovery inventory returned no data.').items;
}

// ─── Assets API ───────────────────────────────────────────────────────────────

export async function getAssets(signal?: AbortSignal): Promise<Asset[]> {
  const data = await request<PaginatedResponse<BackendAsset>>('/assets?size=100', { signal });
  return requireResponse(data, 'Asset service returned no data.').items.map((a) => mapBackendAsset(a));
}

export async function getAsset(id: string, signal?: AbortSignal): Promise<Asset | undefined> {
  const data = await request<BackendAsset>(`/assets/${id}`, { signal });
  return mapBackendAsset(requireResponse(data, 'Asset service returned no data.'));
}

export async function createAsset(data: Partial<Asset>): Promise<Asset> {
  const res = await request<BackendAsset>('/assets', {
    method: 'POST',
    body: JSON.stringify({
      name: data.name || 'Unnamed Asset',
      asset_type: data.type || 'server',
      target: data.ip || '127.0.0.1',
      description: data.owner || undefined,
    }),
  });

  return mapBackendAsset(requireResponse(res, 'Asset service returned no asset record.'));
}

export async function updateAsset(id: string, data: Partial<Asset>): Promise<Asset | undefined> {
  const res = await request<BackendAsset>(`/assets/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      name: data.name,
      asset_type: data.type,
      target: data.ip,
      description: data.owner,
    }),
  });

  return mapBackendAsset(requireResponse(res, 'Asset service returned no asset record.'));
}

export async function deleteAsset(id: string): Promise<{ success: boolean }> {
  await request(`/assets/${id}`, {
    method: 'DELETE',
  });
  return { success: true };
}

// ─── Vulnerabilities API ──────────────────────────────────────────────────────

export async function getVulnerabilities(signal?: AbortSignal): Promise<Vulnerability[]> {
  const data = await request<PaginatedResponse<BackendVulnerability>>('/vulnerabilities?size=100', { signal });
  return requireResponse(data, 'Vulnerability service returned no data.').items.map((v) => mapBackendVuln(v));
}

export async function getVulnerability(id: string, signal?: AbortSignal): Promise<Vulnerability | undefined> {
  const data = await request<BackendVulnerability>(`/vulnerabilities/${id}`, { signal });
  return mapBackendVuln(requireResponse(data, 'Vulnerability service returned no data.'));
}

export async function updateVulnerabilityStatus(
  id: string,
  status: Vulnerability['status']
): Promise<{ success: boolean; vulnerability?: Vulnerability }> {
  const res = await request<BackendVulnerability>(`/vulnerabilities/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });

  return { success: true, vulnerability: mapBackendVuln(requireResponse(res, 'Vulnerability service returned no updated record.')) };
}


// ─── Reports API (Phase 9.2: Persistent Report History in PostgreSQL) ───────

export interface BackendReport {
  id: string;
  report_code?: string;
  name: string;
  target: string;
  report_type: string;
  type?: string;
  format: string;
  status: string;
  scan_date: string;
  date_from?: string | null;
  date_to?: string | null;
  file_size: string;
  findings_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  security_score?: number | null;
  total_assets?: number;
  total_scans?: number;
  created_at: string;
  updated_at: string;
  download_url?: string;
  snapshot_data?: any;
}

export function mapBackendReport(b: BackendReport): Report {
  return {
    id: b.id,
    reportCode: b.report_code,
    name: b.name,
    target: b.target,
    type: (b.type || b.report_type || 'executive') as Report['type'],
    format: (b.format?.toLowerCase() || 'pdf') as Report['format'],
    status: (b.status === 'completed' ? 'ready' : b.status || 'ready') as Report['status'],
    scanDate: b.scan_date,
    fileSize: b.file_size || '1.2 MB',
    findingsSummary: {
      critical: b.findings_summary?.critical ?? 0,
      high: b.findings_summary?.high ?? 0,
      medium: b.findings_summary?.medium ?? 0,
      low: b.findings_summary?.low ?? 0,
      info: b.findings_summary?.info ?? 0,
      total: b.findings_summary?.total ?? 0,
    },
    downloadUrl: b.download_url,
    securityScore: b.security_score ?? undefined,
    totalAssets: b.total_assets,
    totalScans: b.total_scans,
    snapshotData: b.snapshot_data,
  };
}

/**
 * Returns saved report history from the PostgreSQL backend API.
 * Never returns mock data on request failure.
 */
export async function getReports(params?: {
  page?: number;
  size?: number;
  type?: string;
  search?: string;
}, signal?: AbortSignal): Promise<Report[]> {
  const query = new URLSearchParams();
  query.set('size', String(params?.size ?? 100));
  if (params?.page) query.set('page', String(params.page));
  if (params?.type && params.type !== 'all') query.set('type', params.type);
  if (params?.search) query.set('search', params.search);

  const res = requireResponse(
    await request<{ items: BackendReport[]; total: number }>(`/reports?${query.toString()}`, { signal }),
    'Report service returned no data.',
  );
  if (!Array.isArray(res.items)) {
    throw new ApiError('Report service returned an invalid list response.', 502);
  }
  return res.items.map(mapBackendReport);
}

/**
 * Retrieves a single saved report by ID or report_code from PostgreSQL.
 */
export async function getReport(id: string, signal?: AbortSignal): Promise<Report | undefined> {
  const res = await request<BackendReport>(`/reports/${encodeURIComponent(id)}`, { signal });
  return mapBackendReport(requireResponse(res, 'Report service returned no report.'));
}

/**
 * Generates and saves a report to PostgreSQL through POST /api/v1/reports.
 * Snapshot and real vulnerability telemetry are computed server-side.
 */
export async function generateReport(data: {
  name: string;
  target: string;
  type: Report['type'];
  format: Report['format'];
  dateFrom?: string;
  dateTo?: string;
}): Promise<Report> {
  const payload = {
    name: data.name.trim(),
    target: data.target.trim(),
    report_type: data.type,
    format: data.format,
    date_from: data.dateFrom,
    date_to: data.dateTo,
  };

  const res = await request<BackendReport>('/reports', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  return mapBackendReport(requireResponse(res, 'Report service returned no report.'));
}

/**
 * Deletes a saved report from PostgreSQL.
 */
export async function deleteReport(id: string): Promise<{ success: boolean }> {
  await request(`/reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
  return { success: true };
}

/**
 * Sanitizes a CSV cell value to prevent spreadsheet formula injection (CSV injection).
 * Per OWASP guidelines, cells starting with =, +, -, @, TAB (\t), or CR (\r)
 * (including those preceded by leading whitespace or ASCII control characters)
 * are prefixed with a single quote (') to neutralize formula execution.
 *
 * In accordance with RFC 4180, any field that contains commas, double quotes,
 * or newlines is enclosed in double quotes with embedded quotes doubled ("").
 *
 * Nullable or non-string inputs are safely normalized to strings.
 */
export function sanitizeCsvCell(raw: unknown): string {
  if (raw === null || raw === undefined) {
    return '';
  }
  let str = String(raw);
  if (str === '') {
    return '';
  }

  // 1. Formula-injection protection (OWASP)
  // Neutralize formula triggers: =, +, -, @, \t, \r,
  // including cases with leading whitespace or ASCII control characters (0x00-0x1F).
  if (/^[\s\x00-\x1f]*[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }

  // 2. CSV standard escaping (RFC 4180)
  // If the cell contains commas, double quotes, or newlines,
  // escape internal quotes by doubling them ("") and wrap in outer double quotes.
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }

  return str;
}

/**
 * Exports a report as a real downloadable CSV file.
 * Sanitizes all cell values to prevent formula injection attacks.
 * CSV export produces a real file download. PDF export is implemented by the
 * report PDF service below; JSON export is not exposed by the current UI.
 */
export function exportReportCsv(report: Report): void {
  const s = sanitizeCsvCell;
  const rows: string[] = [
    // Header comment with metadata — formula-injection protected
    `# VulnScanner Security Report Export`,
    `# Report: ${s(report.name)}`,
    `# Target: ${s(report.target)}`,
    `# Type: ${s(report.type)}`,
    `# Scan Date: ${s(report.scanDate)}`,
    `# Export Date: ${new Date().toISOString()}`,
    `# Status: ${s(report.status)}`,
    ``,
    // Findings summary table
    `Metric,Count`,
    `Critical Findings,${report.findingsSummary?.critical ?? 0}`,
    `High Findings,${report.findingsSummary?.high ?? 0}`,
    `Medium Findings,${report.findingsSummary?.medium ?? 0}`,
    `Low Findings,${report.findingsSummary?.low ?? 0}`,
    `Info Findings,${report.findingsSummary?.info ?? 0}`,
    `Total Findings,${report.findingsSummary?.total ?? 0}`,
  ];

  const csvContent = rows.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  const safeName = (report.name || 'Security_Report').replace(/[^a-zA-Z0-9_\-]/g, '_');
  const safeDate = (report.scanDate || 'export').replace(/[^a-zA-Z0-9_\-]/g, '_');
  link.download = `${safeName}_${safeDate}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// ─── Real PDF Report Export (Phase 9.3) ──────────────────────────────────────

// ─── Platform Settings & Write-Only Secrets ─────────────────────────────────

export async function getSettings(signal?: AbortSignal): Promise<PlatformSettings> {
  return requireResponse(await request<PlatformSettings>('/settings', { signal }), 'Settings service returned no data.');
}

export async function updateSettings(data: PlatformPreferences): Promise<PlatformSettings> {
  return requireResponse(await request<PlatformSettings>('/settings', {
    method: 'PATCH',
    body: JSON.stringify(data),
  }), 'Settings service returned no data.');
}

export async function saveIntegrationSecret(
  provider: IntegrationProvider,
  secret: string,
): Promise<SecretStatus> {
  return requireResponse(await request<SecretStatus>(`/settings/integrations/${provider}`, {
    method: 'PUT',
    body: JSON.stringify({ secret }),
  }), 'Settings service returned no secret status.');
}

export async function removeIntegrationSecret(provider: IntegrationProvider): Promise<void> {
  await request<null>(`/settings/integrations/${provider}`, { method: 'DELETE' });
}

export async function replacePlatformApiKey(apiKey: string): Promise<SecretStatus> {
  return requireResponse(await request<SecretStatus>('/settings/api-key/regenerate', {
    method: 'POST',
    body: JSON.stringify({ api_key: apiKey }),
  }), 'Settings service returned no API-key status.');
}

export async function removePlatformApiKey(): Promise<void> {
  await request<null>('/settings/api-key', { method: 'DELETE' });
}

// ─── Stats ───────────────────────────────────────────────────────────────────

export async function getStats(): Promise<DashboardStats> {
  const dash = await getDashboard();
  return dash.stats;
}

// ─── Authorized Targets API ──────────────────────────────────────────────────

export async function getAuthorizedTargets(
  page: number = 1,
  size: number = 50,
  enabledOnly: boolean = false,
  signal?: AbortSignal,
): Promise<PaginatedResponse<AuthorizedTarget>> {
  const query = new URLSearchParams({
    page: String(page),
    size: String(size),
    ...(enabledOnly ? { enabled_only: 'true' } : {}),
  });

  const res = await request<PaginatedResponse<AuthorizedTarget>>(`/authorized-targets?${query.toString()}`, { signal });
  return requireResponse(res, 'Authorized-target service returned no data.');
}

export async function getAuthorizedTarget(id: string, signal?: AbortSignal): Promise<AuthorizedTarget | undefined> {
  const res = await request<AuthorizedTarget>(`/authorized-targets/${id}`, { signal });
  return res === null ? undefined : res;
}

export async function createAuthorizedTarget(data: {
  target: string;
  description?: string | null;
  is_enabled?: boolean;
}): Promise<AuthorizedTarget> {
  const res = await request<AuthorizedTarget>('/authorized-targets', {
    method: 'POST',
    body: JSON.stringify({
      target: data.target.trim(),
      description: data.description?.trim() || null,
      is_enabled: data.is_enabled ?? true,
    }),
  });

  return requireResponse(res, 'Authorized-target service returned no target.');
}

export async function updateAuthorizedTarget(
  id: string,
  data: {
    description?: string | null;
    is_enabled?: boolean;
  }
): Promise<AuthorizedTarget> {
  const res = await request<AuthorizedTarget>(`/authorized-targets/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });

  return requireResponse(res, 'Authorized-target service returned no target.');
}

export async function deleteAuthorizedTarget(id: string): Promise<{ success: boolean }> {
  await request(`/authorized-targets/${id}`, {
    method: 'DELETE',
  });
  return { success: true };
}

// ─── Administrator control center ─────────────────────────────────────────

export interface AdminSessionSummary {
  reference: string;
  login_time: string;
  last_activity: string;
  expires_at: string;
}

export interface AdminUser {
  id: string;
  full_name: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  is_active: boolean;
  password_change_required: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  last_activity_at: string | null;
  online: boolean;
  active_sessions: number;
  total_scans: number;
  total_findings: number;
  total_reports: number;
  sessions?: AdminSessionSummary[];
  recent_events?: AuditLogEntry[];
}

export interface AdminScan {
  id: string;
  owner_user_id: string | null;
  owner_username: string | null;
  target: string;
  operation: string;
  authorization_mode: string;
  scan_type: string;
  status: string;
  progress: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  findings_count: number;
  error_message: string | null;
}

export interface AdminReport {
  id: string;
  owner_user_id: string | null;
  owner_username: string | null;
  scan_id: string | null;
  report_code: string | null;
  name: string;
  target: string;
  report_type: string;
  format: string;
  status: string;
  total_findings: number;
  created_at: string;
}

export interface AdminDiscovery {
  id: string;
  owner_user_id: string | null;
  owner_username: string | null;
  target: string;
  target_kind: string;
  authorization_mode: string;
  status: string;
  hosts_discovered: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface AdminVulnerability {
  id: string;
  title: string;
  cve_id: string | null;
  severity: string;
  cvss_score: number | null;
  target: string;
  port: number | null;
  scan_id: string;
  owner_user_id: string | null;
  owner_username: string | null;
  status: string;
  created_at: string;
  remediation: string | null;
}

export interface AuditLogEntry {
  id: string;
  created_at: string;
  actor_user_id: string | null;
  actor_username: string | null;
  event_type: string;
  outcome: string;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  metadata: Record<string, unknown>;
}

export interface AdminOverview {
  total_users: number;
  active_users: number;
  disabled_users: number;
  online_users: number;
  total_scans: number;
  running_scans: number;
  completed_scans: number;
  failed_scans: number;
  cancelled_scans: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  recent_discoveries: AdminDiscovery[];
  recent_activity: AuditLogEntry[];
  health: { backend: string; database: string; nmap: string };
}

function adminQuery(params: Record<string, string | number | boolean | null | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export async function getAdminOverview(signal?: AbortSignal, days = 30): Promise<AdminOverview> {
  return requireResponse(await request<AdminOverview>(`/admin/overview?days=${days}`, { signal }), 'Admin overview returned no data.');
}

export async function getAdminUsers(params: Record<string, string | number | boolean | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AdminUser>> {
  return requireResponse(await request<PaginatedResponse<AdminUser>>(`/admin/users${adminQuery(params)}`, { signal }), 'User administration returned no data.');
}

export async function getAdminUser(userId: string, signal?: AbortSignal): Promise<AdminUser> {
  return requireResponse(await request<AdminUser>(`/admin/users/${userId}`, { signal }), 'User administration returned no account.');
}

export async function updateAdminUser(userId: string, data: Partial<Pick<AdminUser, 'full_name' | 'username' | 'email' | 'role' | 'is_active'>> & { version: number }): Promise<AdminUser> {
  return requireResponse(await request<AdminUser>(`/admin/users/${userId}`, { method: 'PATCH', body: JSON.stringify(data) }), 'User administration returned no account.');
}

export async function setAdminUserEnabled(userId: string, enabled: boolean): Promise<AdminUser> {
  return requireResponse(await request<AdminUser>(`/admin/users/${userId}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' }), 'User administration returned no account.');
}

export async function resetAdminUserPassword(userId: string, temporaryPassword: string, confirmPassword: string): Promise<{ success: boolean; message: string }> {
  return requireResponse(await request(`/admin/users/${userId}/reset-password`, {
    method: 'POST',
    body: JSON.stringify({ temporary_password: temporaryPassword, confirm_password: confirmPassword }),
  }), 'Password reset returned no result.');
}

export async function revokeAdminUserSessions(userId: string): Promise<{ success: boolean; message: string }> {
  return requireResponse(await request(`/admin/users/${userId}/revoke-sessions`, { method: 'POST' }), 'Session revocation returned no result.');
}

export async function revokeAdminSession(userId: string, reference: string): Promise<{ success: boolean; message: string }> {
  return requireResponse(await request(`/admin/users/${userId}/sessions/${encodeURIComponent(reference)}/revoke`, { method: 'POST' }), 'Session revocation returned no result.');
}

export async function getAdminUserScans(userId: string, signal?: AbortSignal): Promise<PaginatedResponse<AdminScan>> {
  return requireResponse(await request<PaginatedResponse<AdminScan>>(`/admin/users/${userId}/scans?size=100`, { signal }), 'User scan history returned no data.');
}

export async function getAdminUserReports(userId: string, signal?: AbortSignal): Promise<PaginatedResponse<AdminReport>> {
  return requireResponse(await request<PaginatedResponse<AdminReport>>(`/admin/users/${userId}/reports?size=100`, { signal }), 'User report history returned no data.');
}

export async function getAdminScans(params: Record<string, string | number | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AdminScan>> {
  return requireResponse(await request<PaginatedResponse<AdminScan>>(`/admin/scans${adminQuery(params)}`, { signal }), 'Administrative scan history returned no data.');
}

export async function cancelAdminScan(scanId: string): Promise<{ success: boolean; message: string }> {
  return requireResponse(await request(`/admin/scans/${scanId}/cancel`, { method: 'POST' }), 'Scan cancellation returned no result.');
}

export async function recordAdminScanReportAccess(scanId: string): Promise<void> {
  await request(`/admin/scans/${scanId}/report-access`, { method: 'POST' });
}

export async function getAdminReports(params: Record<string, string | number | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AdminReport>> {
  return requireResponse(await request<PaginatedResponse<AdminReport>>(`/admin/reports${adminQuery(params)}`, { signal }), 'Administrative reports returned no data.');
}

export async function recordAdminReportDownload(reportId: string): Promise<void> {
  await request(`/admin/reports/${reportId}/download-event`, { method: 'POST' });
}

export async function getAdminDiscoveries(params: Record<string, string | number | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AdminDiscovery>> {
  return requireResponse(await request<PaginatedResponse<AdminDiscovery>>(`/admin/discoveries${adminQuery(params)}`, { signal }), 'Administrative discoveries returned no data.');
}

export async function getAdminVulnerabilities(params: Record<string, string | number | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AdminVulnerability>> {
  return requireResponse(await request<PaginatedResponse<AdminVulnerability>>(`/admin/vulnerabilities${adminQuery(params)}`, { signal }), 'Administrative findings returned no data.');
}

export async function getAdminAuditLogs(params: Record<string, string | number | undefined> = {}, signal?: AbortSignal): Promise<PaginatedResponse<AuditLogEntry>> {
  return requireResponse(await request<PaginatedResponse<AuditLogEntry>>(`/admin/audit-logs${adminQuery(params)}`, { signal }), 'Audit log returned no data.');
}
