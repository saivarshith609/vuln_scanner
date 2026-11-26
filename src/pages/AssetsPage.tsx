import React, { useState } from 'react';
import { useAsync } from '../hooks/useAsync';
import { getAssets, createAsset, deleteAsset } from '../services/api';
import type { Asset, AssetType } from '../types';
import { StateView } from '../components/ui/StateView';
import { Button } from '../components/ui/Button';
import { SearchInput, Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { StatCard } from '../components/ui/StatCard';
import { AssetDrawer } from '../components/dashboard/AssetDrawer';
import { useToast } from '../components/ui/Toast';
import {
  Server, Monitor, Wifi, Globe2, Cloud, Plus,
  Trash2, Eye, RefreshCw, ShieldCheck,
} from 'lucide-react';
import { AuthorizedTargetsManager } from '../components/targets/AuthorizedTargetsManager';

const ASSET_TYPE_ICONS: Record<AssetType, React.ElementType> = {
  server: Server,
  workstation: Monitor,
  network: Wifi,
  web: Globe2,
  cloud: Cloud,
};

const ASSET_TYPES: { type: AssetType | 'all'; label: string }[] = [
  { type: 'all', label: 'All Assets' },
  { type: 'server', label: 'Servers' },
  { type: 'workstation', label: 'Workstations' },
  { type: 'network', label: 'Network Devices' },
  { type: 'web', label: 'Web Applications' },
  { type: 'cloud', label: 'Cloud Assets' },
];

const CRIT_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

export const AssetsPage: React.FC = () => {
  const { showToast } = useToast();
  const { data: apiAssets, state, error, refetch, isRefreshing, isStale, lastUpdated } = useAsync(getAssets);

  const [typeFilter, setTypeFilter] = useState<AssetType | 'all'>('all');
  const [criticFilter, setCriticFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'criticality' | 'status'>('name');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Asset | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'inventory' | 'authorized'>('inventory');

  // Form state
  const [form, setForm] = useState({ name: '', ip: '', type: 'server' as AssetType, os: '', criticality: 'medium', owner: '', location: '', tags: '' });
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const allAssets: Asset[] = apiAssets ?? [];

  const filtered = allAssets
    .filter((a) => {
      const matchType = typeFilter === 'all' || a.type === typeFilter;
      const matchCritic = criticFilter === 'all' || a.criticality === criticFilter;
      const matchSearch = a.name.toLowerCase().includes(search.toLowerCase()) ||
        a.ip.toLowerCase().includes(search.toLowerCase()) ||
        (a.owner || '').toLowerCase().includes(search.toLowerCase());
      return matchType && matchCritic && matchSearch;
    })
    .sort((a, b) => {
      if (sortBy === 'name') return a.name.localeCompare(b.name);
      const critOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      if (sortBy === 'criticality') return critOrder[a.criticality] - critOrder[b.criticality];
      return a.status.localeCompare(b.status);
    });

  const resetFilters = () => {
    setTypeFilter('all');
    setCriticFilter('all');
    setSearch('');
  };

  const hasFilters = typeFilter !== 'all' || criticFilter !== 'all' || search.trim() !== '';

  const criticalCount = allAssets.filter((a) => a.criticality === 'critical').length;
  const scannedCount = allAssets.filter((a) => a.status !== 'unscanned').length;
  const unscannedCount = allAssets.filter((a) => a.status === 'unscanned').length;

  const handleAdd = async () => {
    if (!form.name.trim() || !form.ip.trim()) {
      setFormError('Asset name and IP address or hostname are required.');
      return;
    }
    setFormError(null);
    setIsSaving(true);
    try {
      const newAsset = await createAsset({
        ...form,
        criticality: form.criticality as Asset['criticality'],
        tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
      });
      refetch();
      setIsAddOpen(false);
      setForm({ name: '', ip: '', type: 'server', os: '', criticality: 'medium', owner: '', location: '', tags: '' });
      showToast('success', `Asset "${newAsset.name}" added successfully.`);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to add asset. Please try again.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async (asset: Asset) => {
    setIsDeleting(true);
    try {
      await deleteAsset(asset.id);
      refetch();
      setDeleteTarget(null);
      setDrawerOpen(false);
      showToast('success', `Asset "${asset.name}" deleted.`);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to delete asset. Please try again.');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="animate-fade-in" style={{ padding: 'clamp(16px, 3vw, 24px)', display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.01em' }}>Target Assets</h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
            Monitor infrastructure assets and manage the pre-authorized scan targets allow-list.
          </p>
        </div>
        {activeSubTab === 'inventory' && (
          <div style={{ display: 'flex', gap: '8px' }}>
            <Button variant="outline" size="sm" leftIcon={<RefreshCw size={14} />} onClick={refetch} isLoading={isRefreshing}>Refresh</Button>
            <Button variant="primary" size="sm" leftIcon={<Plus size={14} />} onClick={() => setIsAddOpen(true)}>Add Asset</Button>
          </div>
        )}
      </div>

      {/* Sub-Navigation Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--color-border)', paddingBottom: '8px' }}>
        <button
          type="button"
          onClick={() => setActiveSubTab('inventory')}
          aria-pressed={activeSubTab === 'inventory'}
          style={{
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubTab === 'inventory' ? '1px solid var(--color-brand)' : '1px solid transparent',
            background: activeSubTab === 'inventory' ? 'var(--color-brand-subtle)' : 'transparent',
            color: activeSubTab === 'inventory' ? 'var(--color-brand-light)' : 'var(--color-text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.15s ease',
          }}
        >
          <Server size={16} />
          <span>Infrastructure Inventory ({allAssets.length})</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveSubTab('authorized')}
          aria-pressed={activeSubTab === 'authorized'}
          style={{
            padding: '8px 16px',
            borderRadius: '8px',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubTab === 'authorized' ? '1px solid var(--color-brand)' : '1px solid transparent',
            background: activeSubTab === 'authorized' ? 'var(--color-brand-subtle)' : 'transparent',
            color: activeSubTab === 'authorized' ? 'var(--color-brand-light)' : 'var(--color-text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            transition: 'all 0.15s ease',
          }}
        >
          <ShieldCheck size={16} />
          <span>Authorized Scan Scope</span>
        </button>
      </div>

      {activeSubTab === 'authorized' ? (
        <AuthorizedTargetsManager />
      ) : (
        <>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '16px' }}>
        <StatCard label="Total Assets" value={allAssets.length} subtitle="Registered endpoints" accent="brand" />
        <StatCard label="Critical Assets" value={criticalCount} subtitle="Require immediate attention" accent="critical" />
        <StatCard label="Scanned" value={scannedCount} subtitle={`${unscannedCount} unscanned`} accent="low" />
        <StatCard label="Asset Types" value={new Set(allAssets.map(a => a.type)).size} subtitle="Distinct categories" accent="high" />
      </div>

      {/* Type Filter Pills */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        {ASSET_TYPES.map(({ type, label }) => (
          <button key={type} type="button" onClick={() => setTypeFilter(type as AssetType | 'all')}
            aria-pressed={typeFilter === type}
            style={{ padding: '6px 14px', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', border: typeFilter === type ? '1px solid var(--color-brand)' : '1px solid var(--color-border)', backgroundColor: typeFilter === type ? 'var(--color-brand-subtle)' : 'var(--color-bg-surface)', color: typeFilter === type ? 'var(--color-brand-light)' : 'var(--color-text-secondary)', transition: 'all 0.15s ease' }}>
            {label}
          </button>
        ))}
        <select aria-label="Filter by criticality" value={criticFilter} onChange={(e) => setCriticFilter(e.target.value)}
          style={{ padding: '6px 12px', borderRadius: '20px', fontSize: '0.75rem', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', outline: 'none', cursor: 'pointer' }}>
          <option value="all">All Criticality</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select aria-label="Sort assets" value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
          style={{ padding: '6px 12px', borderRadius: '20px', fontSize: '0.75rem', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', outline: 'none', cursor: 'pointer' }}>
          <option value="name">Sort: Name</option>
          <option value="criticality">Sort: Criticality</option>
          <option value="status">Sort: Status</option>
        </select>
        <div style={{ marginLeft: 'auto', minWidth: '200px', flex: 1, maxWidth: '360px' }}>
          <SearchInput value={search} onChange={setSearch} placeholder="Search name, IP, owner..." />
        </div>
      </div>

      {/* Asset Table */}
      <StateView
        state={state}
        error={error}
        onRetry={refetch}
        isRefreshing={isRefreshing}
        isStale={isStale}
        staleError={error}
        lastUpdated={lastUpdated}
        loadingMessage="Loading assets..."
        isEmpty={filtered.length === 0}
        emptyMessage={hasFilters ? 'No assets match filter criteria' : 'No assets registered yet'}
        emptySubtitle={hasFilters ? 'Try adjusting your type, criticality, or search filters.' : 'Add your first server, workstation, or cloud asset to get started.'}
        emptyAction={
          hasFilters ? (
            <Button variant="outline" size="sm" onClick={resetFilters}>
              Reset All Filters
            </Button>
          ) : (
            <Button variant="primary" size="sm" leftIcon={<Plus size={14} />} onClick={() => setIsAddOpen(true)}>
              Add First Asset
            </Button>
          )
        }
      >
        <div style={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: '16px', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Asset</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Type</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>IP Address</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Criticality</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Status</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Registered</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left' }}>Last Scanned</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((asset) => {
                  const Icon = ASSET_TYPE_ICONS[asset.type];
                  return (
                    <tr key={asset.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', transition: 'background 0.15s' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}>
                      <td style={{ padding: '14px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(59,130,246,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(59,130,246,0.2)' }}>
                            <Icon size={16} color="var(--color-brand)" />
                          </div>
                          <div>
                            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', display: 'block' }}>{asset.name}</span>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>{asset.id}</span>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--color-text-secondary)', textTransform: 'capitalize' }}>{asset.type}</td>
                      <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)', fontSize: '0.75rem' }}>{asset.ip}</td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.75rem', color: CRIT_COLORS[asset.criticality] }}>{asset.criticality.toUpperCase()}</span>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, padding: '3px 8px', borderRadius: '12px', background: asset.status === 'online' ? 'rgba(34,197,94,0.12)' : asset.status === 'scanning' ? 'rgba(59,130,246,0.12)' : asset.status === 'unscanned' ? 'rgba(148,163,184,0.12)' : 'rgba(239,68,68,0.12)', color: asset.status === 'online' ? '#86efac' : asset.status === 'scanning' ? '#93c5fd' : asset.status === 'unscanned' ? '#94a3b8' : '#fca5a5' }}>
                          {asset.status}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                        {asset.created_at ? new Date(asset.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>{asset.lastScanned}</td>
                      <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <Button variant="outline" size="sm" leftIcon={<Eye size={12} />} onClick={() => { setSelectedAsset(asset); setDrawerOpen(true); }}>Details</Button>
                          <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(asset)}><Trash2 size={14} color="var(--color-text-muted)" /></Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </StateView>
        </>
      )}

      {/* Asset Detail Drawer */}
      <AssetDrawer asset={selectedAsset} isOpen={drawerOpen} onClose={() => setDrawerOpen(false)} onDelete={(a) => { setDeleteTarget(a); setDrawerOpen(false); }} onEdit={() => showToast('info', 'Edit functionality coming in next patch.')} onLaunchScan={(target) => { setDrawerOpen(false); showToast('info', `Use the Scan Engine to scan ${target}.`); }} />

      {/* Add Asset Modal */}
      <Modal isOpen={isAddOpen} onClose={() => !isSaving && setIsAddOpen(false)} size="md" title="Add New Asset"
        footer={<><Button variant="ghost" disabled={isSaving} onClick={() => setIsAddOpen(false)}>Cancel</Button><Button variant="primary" isLoading={isSaving} onClick={handleAdd}>Add Asset</Button></>}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <Input label="Asset Name *" error={formError && !form.name.trim() ? formError : undefined} placeholder="e.g. prod-api-cluster-01" value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); setFormError(null); }} />
          <Input label="IP Address / Hostname *" error={formError && !form.ip.trim() ? formError : undefined} placeholder="e.g. 10.142.0.12" value={form.ip} onChange={(e) => { setForm({ ...form, ip: e.target.value }); setFormError(null); }} />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>Asset Type</label>
              <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as AssetType })} style={{ width: '100%', padding: '9px 12px', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '10px', color: 'var(--color-text-primary)', fontSize: '0.875rem', outline: 'none' }}>
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
                <option value="network">Network Device</option>
                <option value="web">Web Application</option>
                <option value="cloud">Cloud Asset</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>Criticality</label>
              <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} style={{ width: '100%', padding: '9px 12px', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '10px', color: 'var(--color-text-primary)', fontSize: '0.875rem', outline: 'none' }}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <Input label="Operating System" placeholder="e.g. Ubuntu 22.04 LTS" value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} />
          <Input label="Owner Team" placeholder="e.g. Platform SRE Team" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          <Input label="Location / Cloud Region" placeholder="e.g. AWS us-east-1" value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })} />
          <Input label="Tags (comma-separated)" placeholder="e.g. Production, Kubernetes, PCI-DSS" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={!!deleteTarget} onClose={() => !isDeleting && setDeleteTarget(null)} size="sm" title="Delete Asset"
        footer={<><Button variant="ghost" disabled={isDeleting} onClick={() => setDeleteTarget(null)}>Cancel</Button><Button variant="danger" isLoading={isDeleting} onClick={() => deleteTarget && handleDelete(deleteTarget)}>Delete</Button></>}>
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Are you sure you want to delete <strong style={{ color: 'var(--color-text-primary)' }}>{deleteTarget?.name}</strong>? This action cannot be undone and will remove all associated scan history.
        </p>
      </Modal>
    </div>
  );
};

export default AssetsPage;
