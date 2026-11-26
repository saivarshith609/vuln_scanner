import React, { useState } from 'react';
import { useAsync } from '../hooks/useAsync';
import { getVulnerabilities, updateVulnerabilityStatus } from '../services/api';
import type { Vulnerability, VulnStatus } from '../types';
import { StateView } from '../components/ui/StateView';
import { StatCard } from '../components/ui/StatCard';
import { SearchInput } from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { VulnDrawer } from '../components/dashboard/VulnDrawer';
import { useToast } from '../components/ui/Toast';
import { RefreshCw, ShieldAlert, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';

type SeverityFilter = 'all' | Vulnerability['severity'];
type StatusFilter = 'all' | VulnStatus;
type SortKey = 'name' | 'severity' | 'cvssScore' | 'asset' | 'discoveredAt' | 'status';
type SortDir = 'asc' | 'desc';

const SEV_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)', text: '#fca5a5' },
  high: { bg: 'rgba(249,115,22,0.12)', text: '#fdba74' },
  medium: { bg: 'rgba(234,179,8,0.12)', text: '#fde047' },
  low: { bg: 'rgba(34,197,94,0.12)', text: '#86efac' },
  info: { bg: 'rgba(59,130,246,0.12)', text: '#93c5fd' },
};

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const STATUS_CONFIG: Record<VulnStatus, { label: string; bg: string; text: string }> = {
  open: { label: 'Open', bg: 'rgba(239,68,68,0.12)', text: '#fca5a5' },
  in_progress: { label: 'In Progress', bg: 'rgba(59,130,246,0.12)', text: '#93c5fd' },
  resolved: { label: 'Resolved', bg: 'rgba(34,197,94,0.12)', text: '#86efac' },
  false_positive: { label: 'False Positive', bg: 'rgba(148,163,184,0.15)', text: '#94a3b8' },
  accepted: { label: 'Accepted Risk', bg: 'rgba(234,179,8,0.12)', text: '#fde047' },
};

const SortIcon: React.FC<{ active: boolean; dir: SortDir }> = ({ active, dir }) => {
  if (!active) return <ChevronsUpDown size={12} color="var(--color-text-muted)" style={{ opacity: 0.4 }} />;
  return dir === 'asc' ? <ChevronUp size={12} color="var(--color-brand-light)" /> : <ChevronDown size={12} color="var(--color-brand-light)" />;
};

export const VulnerabilitiesPage: React.FC = () => {
  const { showToast } = useToast();
  const { data: apiVulns, state, error, refetch, isRefreshing, isStale, lastUpdated } = useAsync(getVulnerabilities);
  const [localStatuses, setLocalStatuses] = useState<Record<string, VulnStatus>>({});
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  const [sevFilter, setSevFilter] = useState<SeverityFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [assetFilter, setAssetFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const vulns: Vulnerability[] = (apiVulns || []).map((v) => ({
    ...v,
    status: localStatuses[v.id] ?? v.status,
  }));

  const assets = Array.from(
    new Set(
      vulns
        .map((v) => v.assetName || v.asset || v.assetTarget || v.target)
        .filter(Boolean)
    )
  );

  const critCount = vulns.filter((v) => v.severity === 'critical').length;
  const highCount = vulns.filter((v) => v.severity === 'high').length;
  const medCount = vulns.filter((v) => v.severity === 'medium').length;
  const lowCount = vulns.filter((v) => v.severity === 'low').length;

  const resetFilters = () => {
    setSevFilter('all');
    setStatusFilter('all');
    setAssetFilter('all');
    setSearch('');
  };

  const hasFilters = sevFilter !== 'all' || statusFilter !== 'all' || assetFilter !== 'all' || search.trim() !== '';

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('asc'); }
  };

  const filtered = vulns
    .filter((v) => {
      const vName = v.name || v.title || '';
      const vAsset = v.assetName || v.asset || v.assetTarget || v.target || '';
      const matchSev = sevFilter === 'all' || v.severity === sevFilter;
      const matchStatus = statusFilter === 'all' || v.status === statusFilter;
      const matchAsset = assetFilter === 'all' || vAsset === assetFilter;
      const matchSearch =
        vName.toLowerCase().includes(search.toLowerCase()) ||
        (v.cve || '').toLowerCase().includes(search.toLowerCase()) ||
        vAsset.toLowerCase().includes(search.toLowerCase());
      return matchSev && matchStatus && matchAsset && matchSearch;
    })
    .sort((a, b) => {
      let cmp = 0;
      const nameA = a.name || a.title || '';
      const nameB = b.name || b.title || '';
      const cvssA = a.cvssScore ?? a.cvss ?? 0;
      const cvssB = b.cvssScore ?? b.cvss ?? 0;
      const assetA = a.assetName || a.asset || a.assetTarget || a.target || '';
      const assetB = b.assetName || b.asset || b.assetTarget || b.target || '';

      if (sortKey === 'name') cmp = nameA.localeCompare(nameB);
      else if (sortKey === 'severity') cmp = SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
      else if (sortKey === 'cvssScore') cmp = cvssB - cvssA;
      else if (sortKey === 'asset') cmp = assetA.localeCompare(assetB);
      else if (sortKey === 'discoveredAt') cmp = a.discoveredAt.localeCompare(b.discoveredAt);
      else if (sortKey === 'status') cmp = a.status.localeCompare(b.status);
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const handleStatusChange = async (id: string, newStatus: VulnStatus) => {
    if (isUpdatingStatus) return;
    setIsUpdatingStatus(true);
    const previousStatus = localStatuses[id] ?? vulns.find((v) => v.id === id)?.status ?? 'open';

    try {
      const res = await updateVulnerabilityStatus(id, newStatus);
      if (res.success) {
        setLocalStatuses((prev) => ({ ...prev, [id]: newStatus }));
        if (selected?.id === id) {
          setSelected((s) => (s ? { ...s, status: newStatus } : s));
        }
        const label = STATUS_CONFIG[newStatus]?.label || newStatus;
        showToast('success', `Triage status updated to ${label}.`);
      } else {
        showToast('error', 'Failed to update triage status on server.');
      }
    } catch (err: unknown) {
      // Preserve previous status on failure
      setLocalStatuses((prev) => ({ ...prev, [id]: previousStatus }));
      const msg = err instanceof Error ? err.message : 'Network error updating triage status';
      showToast('error', msg);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const Th: React.FC<{ label: string; colKey: SortKey }> = ({ label, colKey }) => (
    <th onClick={() => handleSort(colKey)} style={{ padding: '12px 16px', textAlign: 'left', cursor: 'pointer', userSelect: 'none', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
        {label}
        <SortIcon active={sortKey === colKey} dir={sortDir} />
      </div>
    </th>
  );

  return (
    <div className="animate-fade-in" style={{ padding: 'clamp(16px, 3vw, 24px)', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.01em' }}>Vulnerability Management</h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
            Investigate, triage, and track remediation of identified vulnerabilities across all assets.
          </p>
        </div>
        <Button variant="outline" size="sm" leftIcon={<RefreshCw size={14} />} onClick={refetch} isLoading={isRefreshing}>Refresh</Button>
      </div>

      {/* KPI Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '16px' }}>
        <StatCard label="Critical" value={critCount} subtitle="Immediate action required" accent="critical" onClick={() => setSevFilter('critical')} />
        <StatCard label="High" value={highCount} subtitle="High priority issues" accent="high" onClick={() => setSevFilter('high')} />
        <StatCard label="Medium" value={medCount} subtitle="Should be planned" accent="medium" onClick={() => setSevFilter('medium')} />
        <StatCard label="Low" value={lowCount} subtitle="Non-urgent findings" accent="low" onClick={() => setSevFilter('low')} />
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        {(['all', 'critical', 'high', 'medium', 'low', 'info'] as SeverityFilter[]).map((s) => (
          <button key={s} type="button" onClick={() => setSevFilter(s)} aria-pressed={sevFilter === s} style={{ padding: '6px 14px', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', border: sevFilter === s ? `1px solid ${s === 'all' ? 'var(--color-brand)' : SEV_COLORS[s]?.text || 'var(--color-brand)'}` : '1px solid var(--color-border)', backgroundColor: sevFilter === s ? (s === 'all' ? 'var(--color-brand-subtle)' : SEV_COLORS[s]?.bg || 'var(--color-brand-subtle)') : 'var(--color-bg-surface)', color: sevFilter === s ? (s === 'all' ? 'var(--color-brand-light)' : SEV_COLORS[s]?.text || 'var(--color-brand-light)') : 'var(--color-text-secondary)', transition: 'all 0.15s ease' }}>
            {s === 'all' ? 'All Severity' : s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        <select aria-label="Filter by vulnerability status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as StatusFilter)} style={{ padding: '6px 12px', borderRadius: '20px', fontSize: '0.75rem', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', outline: 'none', cursor: 'pointer' }}>
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
          <option value="accepted">Accepted Risk</option>
        </select>
        <select aria-label="Filter by asset" value={assetFilter} onChange={(e) => setAssetFilter(e.target.value)} style={{ padding: '6px 12px', borderRadius: '20px', fontSize: '0.75rem', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', outline: 'none', cursor: 'pointer' }}>
          <option value="all">All Assets</option>
          {assets.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <div style={{ marginLeft: 'auto', minWidth: '200px', flex: 1, maxWidth: '360px' }}>
          <SearchInput value={search} onChange={setSearch} placeholder="Search name, CVE, asset..." />
        </div>
      </div>

      {/* Results count */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <ShieldAlert size={16} color="var(--color-text-muted)" />
        <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Showing <strong style={{ color: 'var(--color-text-primary)' }}>{filtered.length}</strong> of <strong style={{ color: 'var(--color-text-primary)' }}>{vulns.length}</strong> vulnerabilities
        </span>
      </div>

      {/* Table */}
      <StateView
        state={state}
        error={error}
        onRetry={refetch}
        isRefreshing={isRefreshing}
        isStale={isStale}
        staleError={error}
        lastUpdated={lastUpdated}
        loadingMessage="Fetching vulnerabilities..."
        isEmpty={filtered.length === 0}
        emptyMessage={hasFilters ? 'No vulnerabilities match filters' : 'No vulnerabilities recorded'}
        emptySubtitle={hasFilters ? 'Try broadening your filters or reset all search constraints.' : 'Run a target security scan to identify potential vulnerabilities.'}
        emptyAction={
          hasFilters ? (
            <Button variant="outline" size="sm" onClick={resetFilters}>
              Reset All Filters
            </Button>
          ) : undefined
        }
      >
        <div style={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: '16px', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--color-border)', background: 'rgba(255,255,255,0.01)' }}>
                  <Th label="Vulnerability" colKey="name" />
                  <Th label="Severity" colKey="severity" />
                  <Th label="CVSS" colKey="cvssScore" />
                  <Th label="Asset" colKey="asset" />
                  <Th label="Status" colKey="status" />
                  <Th label="Discovered" colKey="discoveredAt" />
                  <th style={{ padding: '12px 16px', textAlign: 'right', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-muted)' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((v) => {
                  const sc = SEV_COLORS[v.severity] || SEV_COLORS.info;
                  const displayAsset = v.assetName || v.asset || v.assetTarget || v.target;
                  const st = STATUS_CONFIG[v.status] || STATUS_CONFIG.open;

                  return (
                    <tr
                      key={v.id}
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer', transition: 'background 0.15s' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                      onClick={() => { setSelected(v); setDrawerOpen(true); }}
                    >
                      <td style={{ padding: '14px 16px' }}>
                        <div>
                          <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', display: 'block', marginBottom: '1px' }}>
                            {v.name || v.title}
                          </span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6875rem', color: 'var(--color-brand-light)', opacity: 0.8 }}>
                            {v.cve || v.id}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ fontSize: '0.6875rem', fontWeight: 700, padding: '3px 8px', borderRadius: '6px', background: sc.bg, color: sc.text }}>
                          {v.severity.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        {(v.cvssScore ?? v.cvss) !== undefined ? (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.875rem', color: (v.cvssScore ?? v.cvss) >= 9 ? '#fca5a5' : (v.cvssScore ?? v.cvss) >= 7 ? '#fdba74' : (v.cvssScore ?? v.cvss) >= 4 ? '#fde047' : '#86efac' }}>
                              {(v.cvssScore ?? v.cvss).toFixed(1)}
                            </span>
                            {v.cvssVector && (
                              <span style={{ fontSize: '0.625rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                                3.1
                              </span>
                            )}
                          </div>
                        ) : <span style={{ color: 'var(--color-text-muted)' }}>—</span>}
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--color-text-secondary)' }}>
                        {displayAsset}
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ fontSize: '0.6875rem', fontWeight: 600, padding: '3px 8px', borderRadius: '12px', background: st.bg, color: st.text }}>
                          {st.label}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                        {v.discoveredAt}
                      </td>
                      <td style={{ padding: '14px 16px', textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <Button variant="outline" size="sm" onClick={() => { setSelected(v); setDrawerOpen(true); }}>
                          Investigate
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </StateView>

      {/* Vuln Investigation Drawer */}
      <VulnDrawer
        vuln={selected}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onStatusChange={handleStatusChange}
        isUpdatingStatus={isUpdatingStatus}
      />
    </div>
  );
};

export default VulnerabilitiesPage;
