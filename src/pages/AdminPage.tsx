import { useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, Ban, Database, Download, Eye,
  KeyRound, Network, RefreshCw, ShieldCheck, UserCog, Users,
} from 'lucide-react';
import { useAuth } from '../components/auth/authContext';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { StateView } from '../components/ui/StateView';
import { StatCard } from '../components/ui/StatCard';
import { useToast } from '../components/ui/Toast';
import { useAsync } from '../hooks/useAsync';
import {
  cancelAdminScan,
  getAdminAuditLogs,
  getAdminDiscoveries,
  getAdminOverview,
  getAdminReports,
  getAdminScans,
  getAdminUser,
  getAdminUserReports,
  getAdminUserScans,
  getAdminUsers,
  getAdminVulnerabilities,
  getDiscoveryHosts,
  getReport,
  getScanReport,
  resetAdminUserPassword,
  recordAdminReportDownload,
  recordAdminScanReportAccess,
  revokeAdminSession,
  revokeAdminUserSessions,
  setAdminUserEnabled,
  updateAdminUser,
  type AdminDiscovery,
  type AdminReport,
  type AdminScan,
  type AdminUser,
  type PaginatedResponse,
} from '../services/api';
import { exportReportPdf } from '../services/pdfExport';
import { downloadScanReportPdf } from '../services/scanReportPdf';
import {
  PASSWORD_REQUIREMENTS_TEXT,
  USERNAME_REQUIREMENTS_TEXT,
  validatePasswordPolicy,
  validateUsernamePolicy,
} from '../utils/authValidation';
import type { DiscoveredHost, Report } from '../types';
import './AdminPage.css';

type AdminSection = 'overview' | 'users' | 'scans' | 'reports' | 'discoveries' | 'vulnerabilities' | 'audit-logs';

const dateTime = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Never';
const shortId = (value?: string | null) => value ? value.slice(0, 8) : '—';

function sectionFromPath(path: string): AdminSection {
  const segment = path.split('/').filter(Boolean)[1];
  return (['users', 'scans', 'reports', 'discoveries', 'vulnerabilities', 'audit-logs'] as AdminSection[]).includes(segment as AdminSection)
    ? segment as AdminSection
    : 'overview';
}

function Status({ value }: { value: string }) {
  const variant = (value === 'online' || value === 'active' || value === 'completed' || value === 'healthy' || value === 'success'
    ? 'low' : value === 'running' || value === 'queued' ? 'medium' : value === 'disabled' || value === 'failed' || value === 'unavailable' ? 'critical' : 'idle') as 'low' | 'medium' | 'critical' | 'idle';
  return <Badge variant={variant}>{value}</Badge>;
}

function AdminNav({ section, navigate }: { section: AdminSection; navigate: (path: string) => void }) {
  const entries: Array<[AdminSection, string]> = [
    ['overview', 'Overview'], ['users', 'Users'], ['scans', 'Scans'], ['reports', 'Reports'],
    ['discoveries', 'Discoveries'], ['vulnerabilities', 'Findings'], ['audit-logs', 'Audit Logs'],
  ];
  return <nav className="vs-admin-nav" aria-label="Administrator sections">
    {entries.map(([id, label]) => <button type="button" key={id} className={section === id ? 'active' : ''} onClick={() => navigate(id === 'overview' ? '/admin' : `/admin/${id}`)}>{label}</button>)}
  </nav>;
}

function OverviewView() {
  const [days, setDays] = useState(30);
  const { data, state, error, refetch, isRefreshing } = useAsync((signal) => getAdminOverview(signal, days), [days]);
  const maximum = Math.max(1, ...Object.values(data?.findings_by_severity || {}));
  return <StateView state={state} error={error} onRetry={refetch} isRefreshing={isRefreshing} loadingMessage="Loading administrator telemetry…">
    {data && <div className="vs-admin-stack">
      <div className="vs-admin-toolbar"><div><h2>Administrative Overview</h2><p>Live account, scan, finding, and platform telemetry.</p></div><select value={days} onChange={(event) => setDays(Number(event.target.value))}><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option></select></div>
      <div className="vs-admin-kpis">
        <StatCard label="Registered Users" value={data.total_users} subtitle={`${data.online_users} currently online`} icon={<Users size={20} />} accent="brand" />
        <StatCard label="Active Accounts" value={data.active_users} subtitle={`${data.disabled_users} disabled`} icon={<ShieldCheck size={20} />} accent="low" />
        <StatCard label="Total Scans" value={data.total_scans} subtitle={`${data.running_scans} queued or running`} icon={<Activity size={20} />} accent="high" />
        <StatCard label="Confirmed Findings" value={data.total_findings} subtitle="Persisted vulnerability records" icon={<AlertTriangle size={20} />} accent="critical" />
      </div>
      <div className="vs-admin-grid-2">
        <section className="vs-admin-panel"><h3>Service health</h3><div className="vs-admin-health"><div><Database size={18} /> Backend <Status value={data.health.backend} /></div><div><Database size={18} /> PostgreSQL <Status value={data.health.database} /></div><div><Network size={18} /> Nmap <Status value={data.health.nmap} /></div></div></section>
        <section className="vs-admin-panel"><h3>Findings by severity</h3>{Object.entries(data.findings_by_severity).map(([severity, count]) => <div className="vs-admin-bar" key={severity}><span>{severity}</span><div><i style={{ width: `${(count / maximum) * 100}%` }} /></div><strong>{count}</strong></div>)}</section>
      </div>
      <section className="vs-admin-panel"><h3>Recent discoveries</h3><AdminTable headers={['ID', 'Requester', 'Scope', 'Status', 'Hosts', 'Started']}>{data.recent_discoveries.map((item) => <tr key={item.id}><td>{shortId(item.id)}</td><td>{item.owner_username || 'Platform admin'}</td><td>{item.target}</td><td><Status value={item.status} /></td><td>{item.hosts_discovered}</td><td>{dateTime(item.started_at || item.created_at)}</td></tr>)}</AdminTable></section>
      <section className="vs-admin-panel"><h3>Recent activity</h3><AdminTable headers={['Time', 'Actor', 'Event', 'Outcome', 'Resource']}>{data.recent_activity.map((item) => <tr key={item.id}><td>{dateTime(item.created_at)}</td><td>{item.actor_username || 'System/API key'}</td><td>{item.event_type}</td><td><Status value={item.outcome} /></td><td>{item.resource_type || '—'} {shortId(item.resource_id)}</td></tr>)}</AdminTable></section>
    </div>}
  </StateView>;
}

function AdminTable({ headers, children }: { headers: string[]; children: React.ReactNode }) {
  return <div className="vs-admin-table-wrap"><table><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{children}</tbody></table></div>;
}

function UsersView({ navigate }: { navigate: (path: string) => void }) {
  const [search, setSearch] = useState('');
  const [role, setRole] = useState('');
  const [accountStatus, setAccountStatus] = useState('');
  const [online, setOnline] = useState('');
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState('created_at');
  const { data, state, error, refetch, isRefreshing } = useAsync((signal) => getAdminUsers({ search, role, account_status: accountStatus, online: online === '' ? undefined : online === 'true', sort, page, size: 20 }, signal), [search, role, accountStatus, online, sort, page]);
  return <div className="vs-admin-stack"><div className="vs-admin-toolbar"><div><h2>User Management</h2><p>Search, inspect, and administer registered accounts.</p></div><Button variant="outline" leftIcon={<RefreshCw size={15} />} onClick={refetch} isLoading={isRefreshing}>Refresh</Button></div>
    <div className="vs-admin-filters"><Input aria-label="Search users" placeholder="Name, username, email, or user ID" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} /><select value={role} onChange={(event) => setRole(event.target.value)}><option value="">All roles</option><option value="user">Users</option><option value="admin">Admins</option></select><select value={accountStatus} onChange={(event) => setAccountStatus(event.target.value)}><option value="">All account states</option><option value="active">Active</option><option value="disabled">Disabled</option></select><select value={online} onChange={(event) => setOnline(event.target.value)}><option value="">Any presence</option><option value="true">Online</option><option value="false">Offline</option></select><select value={sort} onChange={(event) => setSort(event.target.value)}><option value="created_at">Registration date</option><option value="username">Username</option><option value="email">Email</option><option value="last_login_at">Last login</option></select></div>
    <StateView state={state} error={error} onRetry={refetch} isRefreshing={isRefreshing}>{data && <><AdminTable headers={['User', 'Role', 'Status', 'Presence', 'Last login', 'Activity', 'Actions']}>{data.items.map((item) => <tr key={item.id}><td><button className="vs-admin-link" onClick={() => navigate(`/admin/users/${item.id}`)}><strong>{item.full_name}</strong><small>@{item.username} · {item.email}</small></button></td><td>{item.role}</td><td><Status value={item.is_active ? 'active' : 'disabled'} /></td><td><Status value={item.online ? 'online' : 'offline'} /></td><td>{dateTime(item.last_login_at)}</td><td>{dateTime(item.last_activity_at)}</td><td><Button size="sm" variant="ghost" onClick={() => navigate(`/admin/users/${item.id}`)}>Inspect</Button></td></tr>)}</AdminTable><div className="vs-admin-pagination"><span>{data.total} users · Page {data.page} of {data.pages}</span><div><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button><Button size="sm" variant="outline" disabled={page >= data.pages} onClick={() => setPage(page + 1)}>Next</Button></div></div></>}</StateView>
  </div>;
}

function UserDetailView({ userId, navigate }: { userId: string; navigate: (path: string) => void }) {
  const { showToast } = useToast();
  const [tab, setTab] = useState<'profile' | 'scans' | 'reports' | 'sessions' | 'audit'>('profile');
  const [editOpen, setEditOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { data: user, state, error, refetch } = useAsync((signal) => getAdminUser(userId, signal), [userId]);
  const { data: scans, refetch: refetchScans } = useAsync((signal) => getAdminUserScans(userId, signal), [userId]);
  const { data: reports, refetch: refetchReports } = useAsync((signal) => getAdminUserReports(userId, signal), [userId]);
  const act = async (operation: () => Promise<unknown>, success: string) => { setBusy(true); setActionError(null); try { await operation(); showToast('success', success); refetch(); refetchScans(); refetchReports(); } catch (err) { setActionError(err instanceof Error ? err.message : 'Administrative action failed.'); } finally { setBusy(false); } };
  return <StateView state={state} error={error} onRetry={refetch}>{user && <div className="vs-admin-stack">
    <div className="vs-admin-toolbar"><div><button className="vs-admin-back" onClick={() => navigate('/admin/users')}>← Users</button><h2>{user.full_name}</h2><p>@{user.username} · {user.email} · {user.id}</p></div><div className="vs-admin-actions"><Button variant="outline" leftIcon={<UserCog size={15} />} onClick={() => setEditOpen(true)}>Edit</Button><Button variant="outline" leftIcon={<KeyRound size={15} />} onClick={() => setResetOpen(true)}>Reset password</Button><Button variant={user.is_active ? 'danger' : 'primary'} disabled={busy} onClick={() => { if (window.confirm(`${user.is_active ? 'Disable' : 'Enable'} ${user.username}?${user.is_active ? ' Active sessions will be revoked.' : ''}`)) void act(() => setAdminUserEnabled(user.id, !user.is_active), `Account ${user.is_active ? 'disabled' : 'enabled'}.`); }}>{user.is_active ? 'Disable' : 'Enable'}</Button></div></div>
    {actionError && <div className="vs-admin-error" role="alert">{actionError}</div>}
    <div className="vs-admin-tabs">{(['profile', 'scans', 'reports', 'sessions', 'audit'] as const).map((item) => <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{item}</button>)}</div>
    {tab === 'profile' && <div className="vs-admin-grid-2"><section className="vs-admin-panel"><h3>Account</h3><dl className="vs-admin-details"><dt>Role</dt><dd>{user.role}</dd><dt>Status</dt><dd><Status value={user.is_active ? 'active' : 'disabled'} /></dd><dt>Registered</dt><dd>{dateTime(user.created_at)}</dd><dt>Last login</dt><dd>{dateTime(user.last_login_at)}</dd><dt>Last activity</dt><dd>{dateTime(user.last_activity_at)}</dd><dt>Password state</dt><dd>{user.password_change_required ? 'Change required' : 'Current'}</dd><dt>Record version</dt><dd>{user.version}</dd></dl></section><section className="vs-admin-panel"><h3>Owned data</h3><div className="vs-admin-mini-kpis"><div><strong>{user.total_scans}</strong><span>Scans</span></div><div><strong>{user.total_findings}</strong><span>Findings</span></div><div><strong>{user.total_reports}</strong><span>Reports</span></div><div><strong>{user.active_sessions}</strong><span>Sessions</span></div></div><p className="vs-admin-note">Permanent deletion is intentionally unavailable because scan, report, and security audit history must retain attribution. Disable the account instead.</p></section></div>}
    {tab === 'scans' && <ScanTable scans={scans?.items || []} onChanged={refetchScans} />}
    {tab === 'reports' && <ReportTable reports={reports?.items || []} />}
    {tab === 'sessions' && <section className="vs-admin-panel"><div className="vs-admin-toolbar"><div><h3>Active sessions</h3><p>No cookies, tokens, CSRF values, or internal session IDs are exposed.</p></div><Button variant="danger" disabled={!user.active_sessions || busy} onClick={() => { if (window.confirm('Revoke every active session for this user?')) void act(() => revokeAdminUserSessions(user.id), 'All sessions revoked.'); }}>Revoke all</Button></div><AdminTable headers={['Login time', 'Last activity', 'Expires', 'Action']}>{(user.sessions || []).map((session) => <tr key={session.reference}><td>{dateTime(session.login_time)}</td><td>{dateTime(session.last_activity)}</td><td>{dateTime(session.expires_at)}</td><td><Button size="sm" variant="danger" onClick={() => void act(() => revokeAdminSession(user.id, session.reference), 'Session revoked.')}>Revoke</Button></td></tr>)}</AdminTable>{!user.sessions?.length && <p className="vs-admin-empty">No active sessions.</p>}</section>}
    {tab === 'audit' && <section className="vs-admin-panel"><AdminTable headers={['Time', 'Actor', 'Event', 'Outcome', 'Safe metadata']}>{(user.recent_events || []).map((item) => <tr key={item.id}><td>{dateTime(item.created_at)}</td><td>{item.actor_username || 'System/API key'}</td><td>{item.event_type}</td><td><Status value={item.outcome} /></td><td><code>{JSON.stringify(item.metadata)}</code></td></tr>)}</AdminTable>{!user.recent_events?.length && <p className="vs-admin-empty">No audit events recorded for this account.</p>}</section>}
    <EditUserModal user={user} open={editOpen} onClose={() => setEditOpen(false)} onSaved={() => { setEditOpen(false); refetch(); }} />
    <ResetPasswordModal user={user} open={resetOpen} onClose={() => setResetOpen(false)} onSaved={() => { setResetOpen(false); refetch(); showToast('success', 'Temporary password set; sessions revoked.'); }} />
  </div>}</StateView>;
}

function EditUserModal({ user, open, onClose, onSaved }: { user: AdminUser; open: boolean; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({ full_name: user.full_name, username: user.username, email: user.email, role: user.role, is_active: user.is_active });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => setForm({ full_name: user.full_name, username: user.username, email: user.email, role: user.role, is_active: user.is_active }), [user]);
  const save = async () => {
    if (form.username !== user.username) {
      const usernameError = validateUsernamePolicy(form.username);
      if (usernameError) { setError(usernameError); return; }
    }
    if ((form.role !== user.role || form.is_active !== user.is_active) && !window.confirm('This sensitive change will revoke the user’s active sessions. Continue?')) return;
    setBusy(true); setError(null);
    try { await updateAdminUser(user.id, { ...form, version: user.version }); onSaved(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Update failed.'); }
    finally { setBusy(false); }
  };
  return <Modal isOpen={open} onClose={onClose} title="Edit user" footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" isLoading={busy} onClick={() => void save()}>Save changes</Button></>}><div className="vs-admin-form"><Input label="Full name" value={form.full_name} onChange={(event) => setForm({ ...form, full_name: event.target.value })} /><Input label="Username" value={form.username} helperText={USERNAME_REQUIREMENTS_TEXT} onChange={(event) => { setForm({ ...form, username: event.target.value }); setError(null); }} /><Input label="Email" type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /><label>Role<select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value as 'user' | 'admin' })}><option value="user">User</option><option value="admin">Administrator</option></select></label><label className="vs-admin-checkbox"><input type="checkbox" checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.target.checked })} /> Account enabled</label>{error && <div className="vs-admin-error" role="alert">{error}</div>}</div></Modal>;
}

function ResetPasswordModal({ user, open, onClose, onSaved }: { user: AdminUser; open: boolean; onClose: () => void; onSaved: () => void }) {
  const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const save = async () => {
    const policyError = validatePasswordPolicy(password);
    if (policyError) { setError(policyError); return; }
    setBusy(true); setError(null);
    try { await resetAdminUserPassword(user.id, password, confirm); setPassword(''); setConfirm(''); onSaved(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Reset failed.'); }
    finally { setBusy(false); }
  };
  return <Modal isOpen={open} onClose={onClose} title={`Reset password for @${user.username}`} footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="danger" isLoading={busy} disabled={!password || password !== confirm} onClick={() => void save()}>Reset & revoke sessions</Button></>}><div className="vs-admin-form"><p>The temporary password is hashed immediately, never logged, and must be changed after the next login.</p><Input label="Temporary password" type="password" value={password} helperText={PASSWORD_REQUIREMENTS_TEXT} onChange={(event) => { setPassword(event.target.value); setError(null); }} /><Input label="Confirm temporary password" type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} error={confirm && password !== confirm ? 'Passwords do not match.' : undefined} />{error && <div className="vs-admin-error" role="alert">{error}</div>}</div></Modal>;
}

function ScanTable({ scans, onChanged }: { scans: AdminScan[]; onChanged?: () => void }) {
  const { showToast } = useToast();
  const navigateReport = (id: string) => { window.history.pushState({}, '', `/reports/${id}`); window.dispatchEvent(new PopStateEvent('popstate')); };
  const download = async (id: string) => { try { const report = await getScanReport(id); await recordAdminScanReportAccess(id); downloadScanReportPdf(report); showToast('success', 'Scan report PDF download started.'); } catch (err) { showToast('error', err instanceof Error ? err.message : 'Download failed.'); } };
  const cancel = async (id: string) => { if (!window.confirm('Cancel this running scan?')) return; try { await cancelAdminScan(id); showToast('success', 'Cancellation requested.'); onChanged?.(); } catch (err) { showToast('error', err instanceof Error ? err.message : 'Cancellation failed.'); } };
  return <section className="vs-admin-panel"><AdminTable headers={['Scan', 'Owner', 'Target', 'Profile', 'Status', 'Started', 'Duration', 'Findings', 'Actions']}>{scans.map((item) => <tr key={item.id}><td>{shortId(item.id)}</td><td>{item.owner_username || 'Platform admin'}</td><td>{item.target}</td><td>{item.scan_type}<small>{item.authorization_mode}</small></td><td><Status value={item.status} /></td><td>{dateTime(item.started_at || item.created_at)}</td><td>{item.duration_seconds == null ? '—' : `${item.duration_seconds}s`}</td><td>{item.findings_count}</td><td><div className="vs-admin-row-actions"><Button size="sm" variant="ghost" onClick={() => navigateReport(item.id)}>View</Button><Button size="sm" variant="ghost" onClick={() => void download(item.id)}><Download size={14} /></Button>{['queued', 'running'].includes(item.status) && <Button size="sm" variant="danger" onClick={() => void cancel(item.id)}>Cancel</Button>}</div>{item.error_message && <small className="vs-admin-error-text">{item.error_message}</small>}</td></tr>)}</AdminTable>{!scans.length && <p className="vs-admin-empty">No scans match the current filters.</p>}</section>;
}

function ReportTable({ reports }: { reports: AdminReport[] }) {
  const { showToast } = useToast(); const [viewer, setViewer] = useState<Report | null>(null);
  const view = async (id: string) => { try { setViewer((await getReport(id)) || null); } catch (err) { showToast('error', err instanceof Error ? err.message : 'Report unavailable.'); } };
  const download = async (item: AdminReport) => { try { const detailed = await getReport(item.id); if (!detailed) throw new Error('Report unavailable.'); await recordAdminReportDownload(item.id); exportReportPdf(detailed); showToast('success', 'PDF download started.'); } catch (err) { showToast('error', err instanceof Error ? err.message : 'Download failed.'); } };
  return <section className="vs-admin-panel"><AdminTable headers={['Report', 'Owner', 'Target', 'Type', 'Status', 'Findings', 'Created', 'Actions']}>{reports.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.report_code || shortId(item.id)}</small></td><td>{item.owner_username || 'Platform admin'}</td><td>{item.target}</td><td>{item.report_type}</td><td><Status value={item.status} /></td><td>{item.total_findings}</td><td>{dateTime(item.created_at)}</td><td><div className="vs-admin-row-actions"><Button size="sm" variant="ghost" onClick={() => void view(item.id)}><Eye size={14} /> View</Button><Button size="sm" variant="ghost" onClick={() => void download(item)}><Download size={14} /> PDF</Button></div></td></tr>)}</AdminTable>{!reports.length && <p className="vs-admin-empty">No saved reports match the current filters.</p>}<Modal isOpen={Boolean(viewer)} onClose={() => setViewer(null)} title={viewer?.name || 'Report'} size="lg">{viewer && <div className="vs-admin-report-view"><p><strong>Target:</strong> {viewer.target}</p><p><strong>Scan date:</strong> {viewer.scanDate}</p><p><strong>Security score:</strong> {viewer.securityScore ?? 'Unavailable'}</p><pre>{JSON.stringify(viewer.snapshotData || { findingsSummary: viewer.findingsSummary }, null, 2)}</pre></div>}</Modal></section>;
}

function GlobalDataView({ section }: { section: Exclude<AdminSection, 'overview' | 'users'> }) {
  const [search, setSearch] = useState(''); const [status, setStatus] = useState(''); const [severity, setSeverity] = useState(''); const [page, setPage] = useState(1); const [hosts, setHosts] = useState<DiscoveredHost[] | null>(null); const { showToast } = useToast();
  const loader = useMemo(() => async (signal?: AbortSignal): Promise<PaginatedResponse<unknown>> => {
    const common = { page, size: 50 };
    if (section === 'scans') return await getAdminScans({ ...common, target: search, status }, signal);
    if (section === 'reports') return await getAdminReports({ ...common, search, status }, signal);
    if (section === 'discoveries') return await getAdminDiscoveries({ ...common, status }, signal);
    if (section === 'vulnerabilities') return await getAdminVulnerabilities({ ...common, target: search, status, severity }, signal);
    return await getAdminAuditLogs({ ...common, event_type: search, outcome: status }, signal);
  }, [section, search, status, severity, page]);
  const { data, state, error, refetch, isRefreshing } = useAsync(loader, [loader]);
  const items = data?.items || [];
  const inspectDiscovery = async (item: AdminDiscovery) => { try { setHosts(await getDiscoveryHosts(item.id)); } catch (err) { showToast('error', err instanceof Error ? err.message : 'Inventory unavailable.'); } };
  return <div className="vs-admin-stack"><div className="vs-admin-toolbar"><div><h2>{section === 'audit-logs' ? 'Security Audit Log' : `Administrative ${section[0].toUpperCase()}${section.slice(1)}`}</h2><p>Persisted records across all authorized users.</p></div><Button variant="outline" leftIcon={<RefreshCw size={15} />} onClick={refetch} isLoading={isRefreshing}>Refresh</Button></div><div className="vs-admin-filters"><Input placeholder={section === 'audit-logs' ? 'Exact event type' : 'Search target or report'} value={search} onChange={(event) => setSearch(event.target.value)} /><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{section === 'audit-logs' ? <><option value="success">Success</option><option value="failure">Failure</option></> : <><option value="queued">Queued</option><option value="running">Running</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option><option value="ready">Ready</option></>}</select>{section === 'vulnerabilities' && <select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>}</div>
    <StateView state={state} error={error} onRetry={refetch} isRefreshing={isRefreshing}>{data && <>{section === 'scans' ? <ScanTable scans={items as AdminScan[]} onChanged={refetch} /> : section === 'reports' ? <ReportTable reports={items as AdminReport[]} /> : section === 'discoveries' ? <section className="vs-admin-panel"><AdminTable headers={['ID', 'Requester', 'Authorized scope', 'Mode', 'Status', 'Hosts', 'Started', 'Action']}>{(items as AdminDiscovery[]).map((item) => <tr key={item.id}><td>{shortId(item.id)}</td><td>{item.owner_username || 'Platform admin'}</td><td>{item.target}<small>{item.target_kind}</small></td><td>{item.authorization_mode}</td><td><Status value={item.status} /></td><td>{item.hosts_discovered}</td><td>{dateTime(item.started_at || item.created_at)}</td><td><Button size="sm" variant="ghost" onClick={() => void inspectDiscovery(item)}>Inventory</Button></td></tr>)}</AdminTable></section> : section === 'vulnerabilities' ? <section className="vs-admin-panel"><AdminTable headers={['Finding', 'Severity', 'CVSS', 'Target', 'Scan / Owner', 'Status', 'Recorded', 'Remediation']}>{(items as Awaited<ReturnType<typeof getAdminVulnerabilities>>['items']).map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>{item.cve_id || 'No CVE assigned'} · Confirmed finding</small></td><td><Status value={item.severity} /></td><td>{item.cvss_score ?? '—'}</td><td>{item.target}{item.port ? `:${item.port}` : ''}</td><td>{shortId(item.scan_id)}<small>{item.owner_username || 'Platform admin'}</small></td><td>{item.status}</td><td>{dateTime(item.created_at)}</td><td>{item.remediation || 'Not recorded'}</td></tr>)}</AdminTable></section> : <section className="vs-admin-panel"><AdminTable headers={['Time', 'Actor', 'Event', 'Outcome', 'Resource', 'Safe metadata']}>{(items as Awaited<ReturnType<typeof getAdminAuditLogs>>['items']).map((item) => <tr key={item.id}><td>{dateTime(item.created_at)}</td><td>{item.actor_username || 'System/API key'}</td><td>{item.event_type}</td><td><Status value={item.outcome} /></td><td>{item.resource_type || '—'} {shortId(item.resource_id)}</td><td><code>{JSON.stringify(item.metadata)}</code></td></tr>)}</AdminTable></section>}<div className="vs-admin-pagination"><span>{data.total} records · Page {data.page} of {data.pages}</span><div><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button><Button size="sm" variant="outline" disabled={page >= data.pages} onClick={() => setPage(page + 1)}>Next</Button></div></div></>}</StateView>
    <Modal isOpen={hosts !== null} onClose={() => setHosts(null)} title="Discovered host inventory" size="lg">{hosts && <AdminTable headers={['Address', 'Hostname', 'State', 'Last seen']}>{hosts.map((host) => <tr key={host.id}><td>{host.ip_address}</td><td>{host.hostname || '—'}</td><td>{host.discovery_status}</td><td>{dateTime(host.last_seen_at)}</td></tr>)}</AdminTable>}</Modal>
  </div>;
}

export function AdminPage() {
  const { user } = useAuth();
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => { const onPop = () => setPath(window.location.pathname); window.addEventListener('popstate', onPop); return () => window.removeEventListener('popstate', onPop); }, []);
  const navigate = (next: string) => { window.history.pushState({}, '', next); setPath(next); };
  if (user?.role !== 'admin') return <div className="vs-admin-forbidden"><Ban size={30} /><h2>Administrator access required</h2><p>This route is protected by both the client shell and server-side permission checks.</p></div>;
  const section = sectionFromPath(path);
  const userMatch = path.match(/^\/admin\/users\/([^/]+)\/?$/);
  return <div className="vs-admin"><AdminNav section={section} navigate={navigate} />{userMatch ? <UserDetailView userId={decodeURIComponent(userMatch[1])} navigate={navigate} /> : section === 'overview' ? <OverviewView /> : section === 'users' ? <UsersView navigate={navigate} /> : <GlobalDataView section={section} />}</div>;
}

export default AdminPage;
