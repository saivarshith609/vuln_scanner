import React, { useState, useEffect } from 'react';
import {
  X, Globe2, Server, Monitor, Wifi, Cloud,
  Activity, Clock, Radio, Loader, AlertCircle, RefreshCw,
} from 'lucide-react';
import type { Asset, AssetType, ScanResult, Scan } from '../../types';
import { getScanResults, getScans } from '../../services/api';
import { Button } from '../ui/Button';

export interface AssetDrawerProps {
  asset: Asset | null;
  isOpen: boolean;
  onClose: () => void;
  onEdit?: (asset: Asset) => void;
  onDelete?: (asset: Asset) => void;
  onLaunchScan?: (target: string) => void;
}

const ASSET_ICONS: Record<AssetType, React.ElementType> = {
  server: Server,
  workstation: Monitor,
  network: Wifi,
  web: Globe2,
  cloud: Cloud,
};

const STATUS_STYLES: Record<string, { bg: string; color: string }> = {
  completed: { bg: 'rgba(34,197,94,0.12)', color: '#86efac' },
  running: { bg: 'rgba(59,130,246,0.12)', color: '#93c5fd' },
  queued: { bg: 'rgba(234,179,8,0.12)', color: '#fde68a' },
  failed: { bg: 'rgba(239,68,68,0.12)', color: '#fca5a5' },
  cancelled: { bg: 'rgba(148,163,184,0.12)', color: '#94a3b8' },
};

export const AssetDrawer: React.FC<AssetDrawerProps> = ({
  asset,
  isOpen,
  onClose,
  onEdit,
  onDelete,
  onLaunchScan,
}) => {
  const [mounted, setMounted] = useState(false);
  const [visible, setVisible] = useState(false);

  // Real data states
  const [portResults, setPortResults] = useState<ScanResult[]>([]);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [portsLoading, setPortsLoading] = useState(false);
  const [scansLoading, setScansLoading] = useState(false);
  const [portsError, setPortsError] = useState<string | null>(null);
  const [scansError, setScansError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setMounted(true);
      const timer = setTimeout(() => setVisible(true), 20);
      return () => clearTimeout(timer);
    } else {
      setVisible(false);
      const timer = setTimeout(() => setMounted(false), 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  // Fetch discovered ports/services and scan history when drawer opens
  useEffect(() => {
    if (!isOpen || !asset) return;

    let cancelled = false;
    const controller = new AbortController();

    // Fetch discovered ports & services for this asset's target
    setPortsLoading(true);
    setPortsError(null);
    getScanResults({ host: asset.ip }, controller.signal)
      .then((results) => {
        if (!cancelled) {
          // Deduplicate by port+protocol, keep most recent
          const seen = new Map<string, ScanResult>();
          for (const r of results) {
            if (r.port != null) {
              const key = `${r.port}-${r.protocol}`;
              if (!seen.has(key)) seen.set(key, r);
            }
          }
          setPortResults(Array.from(seen.values()));
        }
      })
      .catch((err) => { if (!cancelled) setPortsError(err?.message || 'Failed to fetch port data'); })
      .finally(() => { if (!cancelled) setPortsLoading(false); });

    // Fetch scan history for this target
    setScansLoading(true);
    setScansError(null);
    getScans({ target: asset.ip }, controller.signal)
      .then((scans) => { if (!cancelled) setScanHistory(scans); })
      .catch((err) => { if (!cancelled) setScansError(err?.message || 'Failed to fetch scan history'); })
      .finally(() => { if (!cancelled) setScansLoading(false); });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isOpen, asset]);

  if (!mounted) return null;

  const Icon = asset ? ASSET_ICONS[asset.type] : Server;
  const openPorts = portResults.filter((r) => r.port_state === 'open');
  const latestScan = scanHistory.length > 0 ? scanHistory[0] : null;
  const lastScannedLabel = latestScan?.completedAt
    ? new Date(latestScan.completedAt).toLocaleString()
    : latestScan?.startedAt
      ? new Date(latestScan.startedAt).toLocaleString()
      : 'Never';

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '—';
    try { return new Date(dateStr).toLocaleString(); } catch { return dateStr; }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(6,9,14,0.65)',
          backdropFilter: 'blur(6px)',
          WebkitBackdropFilter: 'blur(6px)',
          zIndex: 200,
          opacity: visible ? 1 : 0,
          transition: 'opacity 0.28s ease',
        }}
      />
      {/* Drawer */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(520px, 100vw)',
          maxWidth: '100vw',
          background: 'var(--color-bg-card)',
          borderLeft: '1px solid var(--color-border)',
          zIndex: 201,
          display: 'flex',
          flexDirection: 'column',
          transform: visible ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.32s cubic-bezier(0.16, 1, 0.3, 1)',
          boxShadow: visible ? '-8px 0 32px rgba(0,0,0,0.65), 0 0 24px rgba(59,130,246,0.1)' : 'none',
        }}
      >
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Icon size={20} color="var(--color-brand)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>{asset?.name}</h3>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)' }}>{asset?.ip}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--color-text-muted)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '6px',
              transition: 'transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), color 0.15s, background-color 0.15s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = 'var(--color-text-primary)';
              e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.08)';
              e.currentTarget.style.transform = 'rotate(90deg)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = 'var(--color-text-muted)';
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.transform = 'none';
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {asset && (
            <>
              {/* Info Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px' }}>
                {[
                  { label: 'Asset Type', val: asset.type.charAt(0).toUpperCase() + asset.type.slice(1) },
                  { label: 'Target', val: asset.ip, mono: true },
                  { label: 'Registered', val: formatDate(asset.created_at) },
                  { label: 'Last Scanned', val: lastScannedLabel },
                  { label: 'Open Ports', val: String(openPorts.length) },
                  { label: 'Owner / Notes', val: asset.owner || '—' },
                ].map(({ label, val, mono }) => (
                  <div key={label} style={{ background: 'var(--color-bg-surface)', borderRadius: '8px', padding: '12px', border: '1px solid var(--color-border)' }}>
                    <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block', marginBottom: '2px' }}>{label}</span>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--color-text-primary)', fontFamily: mono ? 'var(--font-mono)' : 'inherit' }}>{val}</span>
                  </div>
                ))}
              </div>

              {/* Tags */}
              {asset.tags.length > 0 && (
                <div>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block', marginBottom: '8px' }}>Tags</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {asset.tags.map((tag) => (
                      <span key={tag} style={{ fontSize: '0.6875rem', padding: '3px 8px', borderRadius: '4px', background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>{tag}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Discovered Ports & Services ─────────────────────────── */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                  <Radio size={16} color="var(--color-brand)" />
                  <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Discovered Ports & Services
                  </span>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
                    {openPorts.length} open
                  </span>
                </div>

                {portsLoading && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '16px', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                    <Loader size={14} style={{ animation: 'spin 1s linear infinite' }} /> Loading port discoveries…
                  </div>
                )}

                {portsError && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(239,68,68,0.08)', borderRadius: '8px', fontSize: '0.8125rem', color: '#fca5a5' }}>
                    <AlertCircle size={14} /> {portsError}
                  </div>
                )}

                {!portsLoading && !portsError && openPorts.length === 0 && (
                  <div style={{ padding: '16px', background: 'var(--color-bg-surface)', borderRadius: '8px', border: '1px solid var(--color-border)', textAlign: 'center', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                    No open port discoveries recorded for this asset yet.
                  </div>
                )}

                {!portsLoading && openPorts.length > 0 && (
                  <div style={{ background: 'var(--color-bg-surface)', borderRadius: '10px', border: '1px solid var(--color-border)', overflow: 'hidden' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.625rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          <th style={{ padding: '8px 12px', textAlign: 'left' }}>Port</th>
                          <th style={{ padding: '8px 12px', textAlign: 'left' }}>Proto</th>
                          <th style={{ padding: '8px 12px', textAlign: 'left' }}>State</th>
                          <th style={{ padding: '8px 12px', textAlign: 'left' }}>Service</th>
                          <th style={{ padding: '8px 12px', textAlign: 'left' }}>Product / Version</th>
                        </tr>
                      </thead>
                      <tbody>
                        {openPorts.slice(0, 25).map((r) => (
                          <tr key={`${r.port}-${r.protocol}`} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                            <td style={{ padding: '6px 12px', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)', fontWeight: 600 }}>{r.port}</td>
                            <td style={{ padding: '6px 12px', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>{r.protocol || '—'}</td>
                            <td style={{ padding: '6px 12px' }}>
                              <span style={{ padding: '1px 6px', borderRadius: '4px', fontSize: '0.6875rem', fontWeight: 600, background: 'rgba(34,197,94,0.12)', color: '#86efac' }}>
                                {r.port_state}
                              </span>
                            </td>
                            <td style={{ padding: '6px 12px', color: 'var(--color-text-primary)' }}>{r.service_name || '—'}</td>
                            <td style={{ padding: '6px 12px', color: 'var(--color-text-muted)', fontSize: '0.6875rem' }}>
                              {[r.service_product, r.service_version].filter(Boolean).join(' ') || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {openPorts.length > 25 && (
                      <div style={{ padding: '8px 12px', fontSize: '0.6875rem', color: 'var(--color-text-muted)', textAlign: 'center', borderTop: '1px solid var(--color-border)' }}>
                        Showing 25 of {openPorts.length} open ports
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── Scan History ────────────────────────────────────────── */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                  <Activity size={16} color="var(--color-brand)" />
                  <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Scan History
                  </span>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
                    {scanHistory.length} scan{scanHistory.length !== 1 ? 's' : ''}
                  </span>
                </div>

                {scansLoading && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '16px', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                    <Loader size={14} style={{ animation: 'spin 1s linear infinite' }} /> Loading scan history…
                  </div>
                )}

                {scansError && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px', background: 'rgba(239,68,68,0.08)', borderRadius: '8px', fontSize: '0.8125rem', color: '#fca5a5' }}>
                    <AlertCircle size={14} /> {scansError}
                  </div>
                )}

                {!scansLoading && !scansError && scanHistory.length === 0 && (
                  <div style={{ padding: '16px', background: 'var(--color-bg-surface)', borderRadius: '8px', border: '1px solid var(--color-border)', textAlign: 'center', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                    No scans have been run against this asset yet.
                  </div>
                )}

                {!scansLoading && scanHistory.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {scanHistory.slice(0, 10).map((scan) => {
                      const statusStyle = STATUS_STYLES[scan.status] || STATUS_STYLES.cancelled;
                      return (
                        <div
                          key={scan.id}
                          style={{
                            background: 'var(--color-bg-surface)',
                            borderRadius: '8px',
                            border: '1px solid var(--color-border)',
                            padding: '10px 14px',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '12px',
                            transition: 'background 0.15s',
                          }}
                          onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
                          onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--color-bg-surface)')}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {scan.name || `${scan.targetUrl} Scan`}
                              </span>
                              <span style={{
                                fontSize: '0.625rem', fontWeight: 600, padding: '1px 6px',
                                borderRadius: '4px', textTransform: 'uppercase',
                                background: statusStyle.bg, color: statusStyle.color,
                                flexShrink: 0,
                              }}>
                                {scan.status}
                              </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                              <span style={{ textTransform: 'uppercase', fontWeight: 500 }}>{scan.type}</span>
                              <span style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
                                <Clock size={10} />
                                {scan.completedAt ? formatDate(scan.completedAt) : scan.startedAt || '—'}
                              </span>
                              {scan.duration && <span>{scan.duration}</span>}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    {scanHistory.length > 10 && (
                      <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textAlign: 'center', padding: '4px' }}>
                        Showing 10 of {scanHistory.length} scans
                      </div>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            {onDelete && asset && (
              <Button variant="danger" size="sm" onClick={() => onDelete(asset)}>Delete Asset</Button>
            )}
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {onLaunchScan && asset && (
              <Button variant="outline" size="sm" leftIcon={<RefreshCw size={12} />} onClick={() => onLaunchScan(asset.ip)}>Scan Target</Button>
            )}
            {onEdit && asset && (
              <Button variant="primary" size="sm" onClick={() => onEdit(asset)}>Edit Asset</Button>
            )}
          </div>
        </div>
      </div>
    </>
  );
};
