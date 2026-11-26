import { useEffect, useMemo, useState, type PointerEvent } from 'react';
import { Network, Play, RefreshCw, Search, Square, Wifi, X } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { ProgressBar } from '../components/ui/ProgressBar';
import { Badge, StatusBadge } from '../components/ui/Badge';
import { useToast } from '../components/ui/Toast';
import {
  cancelDiscovery,
  createDiscovery,
  createScan,
  getDiscoveries,
  getDiscovery,
  getDiscoveryHosts,
} from '../services/api';
import type { DiscoveredHost, DiscoveryRun, ScanType } from '../types';
import { validateCidrTarget, validateIpRange, validateSingleTarget, type TargetInputMode } from '../utils/targetValidator';
import './DiscoveryPage.css';

const ACTIVE = new Set(['queued', 'running']);

function updateDiscoveryGlow(event: PointerEvent<HTMLElement>) {
  if (event.pointerType === 'touch') return;

  const card = event.currentTarget;
  const bounds = card.getBoundingClientRect();
  const pointerX = event.clientX - bounds.left;
  const pointerY = event.clientY - bounds.top;
  const overControl = event.target instanceof HTMLElement && Boolean(event.target.closest('input, select, button, table'));
  const rotateX = overControl ? 0 : ((bounds.height / 2 - pointerY) / bounds.height) * 2.2;
  const rotateY = overControl ? 0 : ((pointerX - bounds.width / 2) / bounds.width) * 2.8;

  card.style.setProperty('--discovery-pointer-x', `${((pointerX / bounds.width) * 100).toFixed(1)}%`);
  card.style.setProperty('--discovery-pointer-y', `${((pointerY / bounds.height) * 100).toFixed(1)}%`);
  card.style.setProperty('--discovery-tilt-x', `${rotateX.toFixed(2)}deg`);
  card.style.setProperty('--discovery-tilt-y', `${rotateY.toFixed(2)}deg`);
}

function resetDiscoveryGlow(event: PointerEvent<HTMLElement>) {
  const card = event.currentTarget;
  card.style.setProperty('--discovery-pointer-x', '50%');
  card.style.setProperty('--discovery-pointer-y', '50%');
  card.style.setProperty('--discovery-tilt-x', '0deg');
  card.style.setProperty('--discovery-tilt-y', '0deg');
}

function compareIp(left: string, right: string): number {
  const ipv4 = (value: string) => value.split('.').map(Number);
  if (/^\d+(?:\.\d+){3}$/.test(left) && /^\d+(?:\.\d+){3}$/.test(right)) {
    const a = ipv4(left);
    const b = ipv4(right);
    for (let index = 0; index < 4; index += 1) {
      if (a[index] !== b[index]) return a[index] - b[index];
    }
    return 0;
  }
  return left.localeCompare(right, undefined, { numeric: true });
}

export function DiscoveryPage() {
  const { showToast } = useToast();
  const [mode, setMode] = useState<TargetInputMode>('cidr');
  const [singleTarget, setSingleTarget] = useState('');
  const [cidr, setCidr] = useState('');
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd, setRangeEnd] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [profile, setProfile] = useState<ScanType>('quick');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<DiscoveryRun | null>(null);
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [authorizationFilter, setAuthorizationFilter] = useState<'all' | 'authorized' | 'unauthorized'>('all');
  const [sortAscending, setSortAscending] = useState(true);
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
  const [detailHost, setDetailHost] = useState<DiscoveredHost | null>(null);
  const [scanningHost, setScanningHost] = useState<string | null>(null);
  const selectedRunId = selectedRun?.id;
  const selectedRunStatus = selectedRun?.status;

  const loadRuns = async () => {
    const data = await getDiscoveries();
    setRuns(data);
    setSelectedRun((current) => current ? data.find((run) => run.id === current.id) || data[0] || null : data[0] || null);
  };

  // Loading remote history is the external synchronization this effect owns.
  // oxlint-disable-next-line react/set-state-in-effect
  useEffect(() => { void loadRuns().catch((error: unknown) => setInventoryError(error instanceof Error ? error.message : 'Unable to load discovery history.')); }, []);

  useEffect(() => {
    if (!selectedRunId) return;
    let active = true;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const latest = await getDiscovery(selectedRunId, controller.signal);
        const inventory = await getDiscoveryHosts(selectedRunId, {}, controller.signal);
        if (!active) return;
        setSelectedRun(latest);
        setRuns((current) => current.map((run) => run.id === latest.id ? latest : run));
        setHosts(inventory);
        setInventoryError(null);
      } catch (error) {
        if (active && !(error instanceof Error && error.name === 'AbortError')) {
          setInventoryError(error instanceof Error ? error.message : 'Unable to load discovered hosts.');
        }
      }
    };
    void refresh();
    const timer = selectedRunStatus && ACTIVE.has(selectedRunStatus) ? window.setInterval(() => void refresh(), 2000) : undefined;
    return () => { active = false; controller.abort(); if (timer) window.clearInterval(timer); };
  }, [selectedRunId, selectedRunStatus]);

  const submit = async () => {
    setValidationError(null);
    if (!confirmed) return setValidationError('Confirm that you own this target or have explicit permission to assess it.');
    setIsSubmitting(true);
    try {
      if (mode === 'single') {
        const validation = validateSingleTarget(singleTarget);
        if (!validation.isValid) throw new Error(validation.error);
        await createScan({ targetUrl: singleTarget.trim(), type: profile, authorizationMode: 'on_demand', authorizationConfirmed: true });
        showToast('success', `Single-host scan queued for ${singleTarget.trim()}.`);
      } else {
        const validation = mode === 'cidr' ? validateCidrTarget(cidr, 4096) : validateIpRange(rangeStart, rangeEnd, 4096);
        if (!validation.isValid) throw new Error(validation.error);
        const run = await createDiscovery(mode === 'cidr'
          ? { target_type: 'cidr', cidr: cidr.trim(), authorization_mode: 'on_demand', authorization_confirmed: true }
          : { target_type: 'range', start_ip: rangeStart.trim(), end_ip: rangeEnd.trim(), authorization_mode: 'on_demand', authorization_confirmed: true });
        setRuns((current) => [run, ...current]);
        setSelectedRun(run);
        setHosts([]);
        showToast('success', `Host discovery queued for ${run.target}.`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to start the requested operation.';
      setValidationError(message);
      showToast('error', message);
    } finally { setIsSubmitting(false); }
  };

  const stop = async () => {
    if (!selectedRun) return;
    try {
      const updated = await cancelDiscovery(selectedRun.id);
      setSelectedRun(updated);
      showToast('warning', 'Discovery cancellation requested.');
    } catch (error) { showToast('error', error instanceof Error ? error.message : 'Unable to cancel discovery.'); }
  };

  const refreshDiscovery = async () => {
    if (!selectedRun) return;
    setIsSubmitting(true);
    try {
      const run = await createDiscovery(selectedRun.target_kind === 'cidr'
        ? { target_type: 'cidr', cidr: selectedRun.target, authorization_mode: selectedRun.authorization_mode, authorization_confirmed: true }
        : { target_type: 'range', start_ip: selectedRun.range_start || '', end_ip: selectedRun.range_end || '', authorization_mode: selectedRun.authorization_mode, authorization_confirmed: true });
      setRuns((current) => [run, ...current]);
      setSelectedRun(run);
      setHosts([]);
    } catch (error) { showToast('error', error instanceof Error ? error.message : 'Unable to refresh discovery.'); }
    finally { setIsSubmitting(false); }
  };

  const scanHost = async (host: DiscoveredHost) => {
    setScanningHost(host.id);
    try {
      await createScan({ targetUrl: host.ip_address, type: profile, authorizationMode: 'on_demand', authorizationConfirmed: true });
      showToast('success', `Authorized host scan queued for ${host.ip_address}.`);
    } catch (error) { showToast('error', error instanceof Error ? error.message : 'Unable to scan host.'); }
    finally { setScanningHost(null); }
  };

  const visibleHosts = useMemo(() => hosts
    .filter((host) => authorizationFilter === 'all' || (authorizationFilter === 'authorized' ? host.authorized : !host.authorized))
    .filter((host) => `${host.ip_address} ${host.hostname || ''} ${host.mac_address || ''} ${host.vendor || ''}`.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => compareIp(a.ip_address, b.ip_address) * (sortAscending ? 1 : -1)),
  [hosts, search, authorizationFilter, sortAscending]);

  return <div className="vs-discovery-page">
    <section className="vs-discovery-hero vs-discovery-glow-card" onPointerMove={updateDiscoveryGlow} onPointerLeave={resetDiscoveryGlow}>
      <div className="vs-discovery-hero__copy"><span className="vs-discovery-eyebrow">Authorized host inventory</span><h2>Network Discovery</h2><p>Discover responding hosts within an explicitly authorized LAN, Wi-Fi, enterprise, lab, or remote network scope.</p></div>
      <div className="vs-discovery-hero__summary">
        <div><strong>{runs.length}</strong><span>Discovery runs</span></div>
        <div><strong>{hosts.length}</strong><span>Responding hosts</span></div>
        <span className="vs-discovery-hero__icon"><Network size={26} /></span>
      </div>
    </section>

    <section className="vs-discovery-panel vs-discovery-panel--configure vs-discovery-glow-card vs-discovery-glow-card--static">
      <div className="vs-discovery-panel__intro"><div><span className="vs-discovery-eyebrow">Discovery configuration</span><h3>Authorized target scope</h3></div><p>Choose a target format and confirm authorization before execution.</p></div>
      <div className="vs-discovery-modes" role="tablist">
        {([['single', 'Single host'], ['cidr', 'CIDR subnet'], ['range', 'IP address range']] as const).map(([value, label]) =>
          <button key={value} type="button" role="tab" aria-selected={mode === value} className={mode === value ? 'active' : ''} onClick={() => { setMode(value); setValidationError(null); setConfirmed(false); }}>{label}</button>)}
      </div>
      {mode === 'single' ? <Input label="Single IPv4, IPv6, or hostname" value={singleTarget} onChange={(event) => setSingleTarget(event.target.value)} placeholder="host.internal or 192.168.1.20" helperText="Runs a normal persisted host scan without network discovery." />
        : mode === 'cidr' ? <Input label="Authorized CIDR subnet" value={cidr} onChange={(event) => setCidr(event.target.value)} placeholder="192.168.1.0/24" helperText="Uses Nmap -sn host discovery only. Maximum 4,096 addresses." />
          : <div className="vs-discovery-range"><Input label="Range start IP" value={rangeStart} onChange={(event) => setRangeStart(event.target.value)} placeholder="192.168.1.10" /><Input label="Range end IP" value={rangeEnd} onChange={(event) => setRangeEnd(event.target.value)} placeholder="192.168.1.50" /></div>}
      <div className="vs-discovery-controls">
        <label>Host scan profile <select value={profile} onChange={(event) => setProfile(event.target.value as ScanType)}><option value="quick">Quick Recon</option><option value="full">Full TCP Suite</option></select></label>
        <label className="vs-discovery-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I own this target or have explicit permission to assess it.</label>
        <Button className="vs-discovery-primary-action" size="lg" leftIcon={mode === 'single' ? <Play size={17} /> : <Wifi size={17} />} onClick={submit} isLoading={isSubmitting}>{mode === 'single' ? 'Scan Host' : 'Start Discovery'}</Button>
      </div>
      {validationError && <div className="vs-discovery-error" role="alert">{validationError}</div>}
    </section>

    <section className="vs-discovery-panel vs-discovery-panel--runs vs-discovery-glow-card" onPointerMove={updateDiscoveryGlow} onPointerLeave={resetDiscoveryGlow}>
      <div className="vs-discovery-heading"><div><span className="vs-discovery-eyebrow">Execution history</span><h3>Discovery Runs</h3><p>Host discovery does not perform a port scan.</p></div><div className="vs-discovery-actions"><select aria-label="Select discovery run" value={selectedRun?.id || ''} onChange={(event) => setSelectedRun(runs.find((run) => run.id === event.target.value) || null)}><option value="">No discovery selected</option>{runs.map((run) => <option key={run.id} value={run.id}>{run.target} · {run.status}</option>)}</select>{selectedRun && !ACTIVE.has(selectedRun.status) && <Button className="vs-discovery-refresh-action" variant="outline" leftIcon={<RefreshCw size={15} />} onClick={refreshDiscovery}>Refresh Discovery</Button>}{selectedRun && ACTIVE.has(selectedRun.status) && <Button className="vs-discovery-cancel-action" variant="danger" leftIcon={<Square size={15} />} onClick={stop}>Cancel</Button>}</div></div>
      {selectedRun ? <><div className="vs-discovery-status"><div><strong>{selectedRun.target}</strong><StatusBadge status={selectedRun.status} size="sm" />{selectedRun.partial_results && <Badge variant="medium">Partial results</Badge>}</div><ProgressBar value={selectedRun.progress} animated={selectedRun.status === 'running'} /></div>{selectedRun.error_message && <div className="vs-discovery-error">{selectedRun.error_message}</div>}</> : <p className="vs-discovery-empty">No discovery runs yet. Authorize a CIDR scope, then start discovery.</p>}
    </section>

    <section className="vs-discovery-panel vs-discovery-panel--inventory vs-discovery-glow-card vs-discovery-glow-card--static">
      <div className="vs-discovery-heading"><div><span className="vs-discovery-eyebrow">Live asset view</span><h3>Responding Host Inventory</h3><p>{selectedHosts.size} selected · {visibleHosts.length} shown</p></div><div className="vs-discovery-actions"><label className="vs-discovery-search"><Search size={15} /><input aria-label="Search discovered hosts" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IP, hostname, MAC, vendor" /></label><select aria-label="Filter hosts by authorization" value={authorizationFilter} onChange={(event) => setAuthorizationFilter(event.target.value as typeof authorizationFilter)}><option value="all">All authorization states</option><option value="authorized">Authorized only</option><option value="unauthorized">Unauthorized only</option></select></div></div>
      {inventoryError && <div className="vs-discovery-error">{inventoryError}</div>}
      <div className="vs-discovery-table-wrap"><table><thead><tr><th>Select</th><th><button type="button" onClick={() => setSortAscending((value) => !value)}>IP address {sortAscending ? '↑' : '↓'}</button></th><th>Hostname</th><th>MAC address</th><th>Vendor</th><th>Status</th><th>Last seen</th><th>Authorization</th><th>Actions</th></tr></thead><tbody>{visibleHosts.map((host) => <tr key={host.id}><td><input type="checkbox" aria-label={`Select ${host.ip_address}`} checked={selectedHosts.has(host.id)} onChange={(event) => setSelectedHosts((current) => { const next = new Set(current); if (event.target.checked) next.add(host.id); else next.delete(host.id); return next; })} /></td><td className="mono">{host.ip_address}</td><td>{host.hostname || '—'}</td><td className="mono">{host.mac_address || '—'}</td><td>{host.vendor || '—'}</td><td><Badge variant="completed">{host.discovery_status}</Badge></td><td>{new Date(host.last_seen_at).toLocaleString()}</td><td><Badge variant={host.authorized ? 'completed' : 'medium'}>{host.authorized ? 'Authorized' : 'Not authorized'}</Badge></td><td><div className="vs-discovery-row-actions"><Button size="sm" variant="ghost" onClick={() => setDetailHost(host)}>Details</Button><Button size="sm" onClick={() => scanHost(host)} isLoading={scanningHost === host.id} disabled={!host.authorized}>Scan Host</Button></div></td></tr>)}</tbody></table>{selectedRun && !ACTIVE.has(selectedRun.status) && visibleHosts.length === 0 && <div className="vs-discovery-empty">No responding hosts were reported. Firewalls, sleeping devices, isolation, or blocked probes can prevent discovery; this is not proof that hosts are offline.</div>}</div>
    </section>

    <div className="vs-discovery-note">Discovery inventory contains only hosts Nmap reported as responding. MAC addresses and vendors are generally available only on directly connected network segments. Remote, firewalled, sleeping, or isolated hosts may not appear.</div>

    <Modal isOpen={Boolean(detailHost)} onClose={() => setDetailHost(null)} title={<span>Host details</span>} footer={<Button variant="ghost" leftIcon={<X size={14} />} onClick={() => setDetailHost(null)}>Close</Button>}><dl className="vs-discovery-details"><dt>IP address</dt><dd>{detailHost?.ip_address}</dd><dt>Hostname</dt><dd>{detailHost?.hostname || 'Not reported'}</dd><dt>MAC address</dt><dd>{detailHost?.mac_address || 'Not reported'}</dd><dt>Vendor</dt><dd>{detailHost?.vendor || 'Not reported'}</dd><dt>Last seen</dt><dd>{detailHost ? new Date(detailHost.last_seen_at).toLocaleString() : ''}</dd></dl></Modal>
  </div>;
}
