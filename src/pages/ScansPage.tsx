import React, { useState } from 'react';
import { useScans } from '../store/ScanContext';
import { Button } from '../components/ui/Button';
import { StatusBadge, Badge } from '../components/ui/Badge';
import { ProgressBar } from '../components/ui/ProgressBar';
import { StatCard } from '../components/ui/StatCard';
import { SearchInput } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { StateView } from '../components/ui/StateView';
import { useToast } from '../components/ui/Toast';
import type { Scan, ScanResult, ScanStatus, ScanType } from '../types';
import { getScan, getScanResults } from '../services/api';
import {
  Play,
  RotateCw,
  Square,
  Trash2,
  Terminal,
  Grid,
  List,
  Clock,
  RefreshCw,
  SearchX,
  FileText,
} from 'lucide-react';
import './ScansPage.css';

const getNmapCommandString = (type: ScanType, target: string): string => {
  switch (type) {
    case 'quick':
      return `nmap -sV -T3 -F -oX - ${target}`;
    case 'network':
      return `nmap -sn -oX - ${target}`;
    case 'full':
      return `nmap -sV -T3 -p- -oX - ${target}`;
    default:
      return `nmap -sV -T3 -F -oX - ${target}`;
  }
};

const handleScanCardPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
  if (event.pointerType === 'touch') return;

  const card = event.currentTarget;
  const bounds = card.getBoundingClientRect();
  const pointerX = event.clientX - bounds.left;
  const pointerY = event.clientY - bounds.top;
  const rotateX = ((bounds.height / 2 - pointerY) / bounds.height) * 5;
  const rotateY = ((pointerX - bounds.width / 2) / bounds.width) * 6;

  card.style.setProperty('--scan-tilt-x', `${rotateX.toFixed(2)}deg`);
  card.style.setProperty('--scan-tilt-y', `${rotateY.toFixed(2)}deg`);
  card.style.setProperty('--scan-pointer-x', `${((pointerX / bounds.width) * 100).toFixed(1)}%`);
  card.style.setProperty('--scan-pointer-y', `${((pointerY / bounds.height) * 100).toFixed(1)}%`);
};

const resetScanCardTilt = (event: React.PointerEvent<HTMLDivElement>) => {
  const card = event.currentTarget;
  card.style.setProperty('--scan-tilt-x', '0deg');
  card.style.setProperty('--scan-tilt-y', '0deg');
  card.style.setProperty('--scan-pointer-x', '50%');
  card.style.setProperty('--scan-pointer-y', '50%');
};

export interface ScansPageProps {
  onOpenNewScanModal: () => void;
  onViewReport?: (scanId: string) => void;
}

export const ScansPage: React.FC<ScansPageProps> = ({ onOpenNewScanModal, onViewReport }) => {
  const { scans, isLoading, isRefreshing, isStale, lastUpdated, error, stopScan, rerunScan, deleteScan, refreshScans } = useScans();
  const { showToast } = useToast();

  const [statusFilter, setStatusFilter] = useState<ScanStatus | 'all'>('all');
  const [typeFilter, setTypeFilter] = useState<ScanType | 'all'>('all');
  const [search, setSearch] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  // Scan Results state
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [resultsError, setResultsError] = useState<string | null>(null);

  const selectedScanId = selectedScan?.id;

  // Synchronize selected scan with GET /api/v1/scans/{scan_id}
  React.useEffect(() => {
    if (!selectedScanId) return;

    let isMounted = true;
    const controller = new AbortController();
    let requestInFlight = false;
    const fetchLatest = async () => {
      if (requestInFlight) return;
      requestInFlight = true;
      try {
        const fresh = await getScan(selectedScanId, controller.signal);
        if (isMounted && fresh) {
          setSelectedScan(fresh);
        }
      } catch {
        // Poll failures retain the last confirmed scan state.
      } finally {
        requestInFlight = false;
      }
    };

    void fetchLatest();

    const isActive = selectedScan?.status === 'queued' || selectedScan?.status === 'running';
    if (!isActive) {
      return () => {
        isMounted = false;
        controller.abort();
      };
    }

    const interval = setInterval(() => void fetchLatest(), 2000);
    return () => {
      isMounted = false;
      clearInterval(interval);
      controller.abort();
    };
  }, [selectedScanId, selectedScan?.status]);

  React.useEffect(() => {
    if (!selectedScanId) {
      setScanResults([]);
      setResultsError(null);
      return;
    }

    let isMounted = true;
    const controller = new AbortController();
    setLoadingResults(true);
    setResultsError(null);

    getScanResults(selectedScanId, controller.signal)
      .then((items) => {
        if (isMounted) {
          setScanResults(items);
          setLoadingResults(false);
        }
      })
      .catch((err: unknown) => {
        if (isMounted && !(err instanceof Error && err.name === 'AbortError')) {
          setResultsError(err instanceof Error ? err.message : 'Failed to fetch scan results');
          setLoadingResults(false);
        }
      });

    return () => {
      isMounted = false;
      controller.abort();
    };
  }, [selectedScanId, selectedScan?.status]);

  // UX Confirmation dialog states
  const [stopTargetScan, setStopTargetScan] = useState<Scan | null>(null);
  const [deleteTargetScan, setDeleteTargetScan] = useState<Scan | null>(null);
  const [isAborting, setIsAborting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const resetFilters = () => {
    setStatusFilter('all');
    setTypeFilter('all');
    setSearch('');
  };

  const hasFilters = statusFilter !== 'all' || typeFilter !== 'all' || search.trim() !== '';

  const handleRefresh = async () => {
    try {
      await refreshScans();
      showToast('info', 'Scan engine workers and pipeline states synced.');
    } catch (err: unknown) {
      showToast('error', err instanceof Error ? err.message : 'Failed to refresh scans.');
    }
  };

  const handleRerun = async (scan: Scan) => {
    try {
      await rerunScan(scan.id);
      showToast('info', `Scan "${scan.name}" re-initialized.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to re-run scan';
      showToast('error', msg);
    }
  };

  const confirmStop = async () => {
    if (stopTargetScan) {
      setIsAborting(true);
      try {
        await stopScan(stopTargetScan.id);
        showToast('warning', `Scan "${stopTargetScan.name}" cancellation confirmed.`);
        setStopTargetScan(null);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to abort scan';
        showToast('error', msg);
      } finally {
        setIsAborting(false);
      }
    }
  };

  const confirmDelete = async () => {
    if (deleteTargetScan) {
      setIsDeleting(true);
      try {
        await deleteScan(deleteTargetScan.id);
        showToast('success', `Scan "${deleteTargetScan.name}" permanently deleted.`);
        setDeleteTargetScan(null);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to delete scan';
        showToast('error', msg);
      } finally {
        setIsDeleting(false);
      }
    }
  };

  // Filtered scans
  const filteredScans = scans.filter((s) => {
    const matchesStatus = statusFilter === 'all' || s.status === statusFilter;
    const matchesType = typeFilter === 'all' || s.type === typeFilter;
    const matchesSearch =
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      s.targetUrl.toLowerCase().includes(search.toLowerCase()) ||
      s.id.toLowerCase().includes(search.toLowerCase());
    return matchesStatus && matchesType && matchesSearch;
  });

  // Aggregated counters
  const totalScans = scans.length;
  const runningScans = scans.filter((s) => s.status === 'running').length;
  const completedScans = scans.filter((s) => s.status === 'completed').length;
  const totalFindings = scans.reduce((acc, s) => acc + s.findings.total, 0);

  return (
    <div className="vs-scans-container animate-fade-in">
      {/* Top Header */}
      <div className="vs-scans-header">
        <div>
          <h2 className="vs-scans-header__title">Scan Engine Management</h2>
          <p className="vs-scans-header__subtitle">
            Orchestrate continuous reconnaissance, inspect pipeline run logs, and manage targeted vulnerability scans
          </p>
        </div>

        <div className="vs-scans-header__actions">
          <Button
            variant="outline"
            size="md"
            className="vs-scan-header-action vs-scan-header-action--refresh"
            leftIcon={<RefreshCw size={16} className={isRefreshing ? 'animate-spin' : ''} />}
            onClick={handleRefresh}
            isLoading={isRefreshing}
          >
            Refresh
          </Button>

          <Button
            variant="primary"
            size="lg"
            className="vs-scan-header-action vs-scan-header-action--launch"
            leftIcon={<Play size={18} />}
            onClick={onOpenNewScanModal}
          >
            Launch New Scan
          </Button>
        </div>
      </div>

      {/* Summary KPI Counters */}
      <div className="vs-scans-stats-row">
        <div className="vs-scans-stat-stage" style={{ '--scan-enter-delay': '0ms' } as React.CSSProperties}>
          <StatCard label="Total Scans Executed" value={totalScans} subtitle="All historical sessions" accent="brand" />
        </div>
        <div className="vs-scans-stat-stage" style={{ '--scan-enter-delay': '90ms' } as React.CSSProperties}>
          <StatCard
            label="Active Engine Tasks"
            value={`${runningScans} Running`}
            subtitle="Distributed across worker pools"
            accent="low"
            trend={{ value: `${runningScans} live`, direction: 'neutral' }}
          />
        </div>
        <div className="vs-scans-stat-stage" style={{ '--scan-enter-delay': '180ms' } as React.CSSProperties}>
          <StatCard label="Completed Audits" value={completedScans} subtitle="Reports compiled & archived" accent="medium" />
        </div>
        <div className="vs-scans-stat-stage" style={{ '--scan-enter-delay': '270ms' } as React.CSSProperties}>
          <StatCard label="Total Vulnerabilities" value={totalFindings} subtitle="Across all target runs" accent="critical" />
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="vs-scans-toolbar">
        <div className="vs-scans-filter-group">
          {(['all', 'running', 'completed', 'cancelled', 'failed'] as const).map((st) => (
            <button
              key={st}
              type="button"
              className={`vs-filter-pill vs-filter-pill--${st} ${statusFilter === st ? 'vs-filter-pill--active' : ''}`}
              onClick={() => setStatusFilter(st)}
              aria-pressed={statusFilter === st}
            >
              {st}
            </button>
          ))}

          <div style={{ width: '1px', height: '20px', background: 'var(--color-border)', margin: '0 4px' }} />

          <select
            className="vs-scans-profile-select"
            value={typeFilter}
            aria-label="Filter scans by engine profile"
            onChange={(e) => setTypeFilter(e.target.value as ScanType | 'all')}
          >
            <option value="all">All Engine Profiles</option>
            <option value="quick">Quick Recon (-sV -T3 -F)</option>
            <option value="network">Network Discovery (-sn)</option>
            <option value="full">Full Suite (-sV -T3 -p-)</option>
          </select>
        </div>

        <div className="vs-scans-toolbar-right">
          <div style={{ minWidth: '240px' }}>
            <SearchInput
              value={search}
              onChange={setSearch}
              placeholder="Search target, name, or SCAN-ID..."
            />
          </div>

          <div className="vs-view-toggle">
            <button
              type="button"
              className={`vs-view-btn ${viewMode === 'grid' ? 'vs-view-btn--active' : ''}`}
              onClick={() => setViewMode('grid')}
              title="Grid card view"
              aria-label="Grid view"
              aria-pressed={viewMode === 'grid'}
            >
              <Grid size={16} />
            </button>
            <button
              type="button"
              className={`vs-view-btn ${viewMode === 'table' ? 'vs-view-btn--active' : ''}`}
              onClick={() => setViewMode('table')}
              title="Table view"
              aria-label="Table view"
              aria-pressed={viewMode === 'table'}
            >
              <List size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* Loading / Error / Empty State / Grid / Table Views */}
      {!isLoading && scans.length > 0 && filteredScans.length > 0 && (
        <StateView
          state="success"
          isStale={isStale}
          staleError={error}
          isRefreshing={isRefreshing}
          lastUpdated={lastUpdated}
          onRetry={refreshScans}
        >
          <div />
        </StateView>
      )}
      {isLoading ? (
        <StateView state="loading" loadingMessage="Fetching scan pipelines and telemetry...">
          <div />
        </StateView>
      ) : error && scans.length === 0 ? (
        <StateView state="error" error={error} onRetry={refreshScans}>
          <div />
        </StateView>
      ) : filteredScans.length === 0 ? (
        <StateView
          state="success"
          isStale={isStale}
          staleError={error}
          isRefreshing={isRefreshing}
          lastUpdated={lastUpdated}
          onRetry={refreshScans}
          isEmpty={true}
          icon={<SearchX size={24} color="var(--color-text-muted)" />}
          emptyMessage={hasFilters ? 'No scan pipelines match criteria' : 'No security scans executed yet'}
          emptySubtitle={
            hasFilters
              ? 'No active runs match the selected status, profile, or search term.'
              : 'Launch your first automated scan to discover vulnerabilities across your perimeter.'
          }
          emptyAction={
            hasFilters ? (
              <Button variant="outline" size="sm" onClick={resetFilters}>
                Clear All Filters
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                leftIcon={<Play size={14} />}
                onClick={onOpenNewScanModal}
              >
                Launch New Scan
              </Button>
            )
          }
        >
          <div />
        </StateView>
      ) : viewMode === 'grid' ? (
        <div className="vs-scans-grid">
          {filteredScans.map((scan, index) => (
            <div
              key={scan.id}
              className="vs-scan-card-stage"
              style={{ '--scan-enter-delay': `${380 + Math.min(index, 10) * 85}ms` } as React.CSSProperties}
            >
              <div
                className={`vs-scan-item-card vs-scan-item-card--${scan.status}`}
                onPointerMove={handleScanCardPointerMove}
                onPointerLeave={resetScanCardTilt}
              >
              <div className="vs-scan-card__header">
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)' }}>
                      {scan.id}
                    </span>
                    <Badge variant="info" size="sm">
                      {scan.type}
                    </Badge>
                  </div>
                  <h3 className="vs-scan-card__title" style={{ marginTop: '4px' }}>
                    {scan.name}
                  </h3>
                  <span className="vs-scan-card__target">{scan.targetUrl}</span>
                </div>
                <StatusBadge status={scan.status} size="sm" />
              </div>

              {/* Progress Bar */}
              <div className="vs-scan-card__progress">
                <ProgressBar
                  value={scan.progress}
                  variant={scan.status === 'running' ? 'primary' : scan.status === 'completed' ? 'low' : 'medium'}
                  animated={scan.status === 'running'}
                  size="md"
                />
              </div>

              {/* Meta & Findings Pills */}
              <div className="vs-scan-card__summary-row">
                <div className="vs-scan-card__meta">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Clock size={12} /> {scan.duration || '00:00:00'}
                  </span>
                  <span>{scan.startedAt}</span>
                </div>

                <div className="vs-scan-card__findings">
                  {scan.findings.critical > 0 && (
                    <span className="vs-findings-pill vs-findings-pill--crit">
                      {scan.findings.critical} Crit
                    </span>
                  )}
                  {scan.findings.high > 0 && (
                    <span className="vs-findings-pill vs-findings-pill--high">
                      {scan.findings.high} High
                    </span>
                  )}
                  {scan.findings.medium > 0 && (
                    <span className="vs-findings-pill vs-findings-pill--med">
                      {scan.findings.medium} Med
                    </span>
                  )}
                  {scan.findings.total === 0 && (
                    <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                      No flaws detected
                    </span>
                  )}
                </div>
              </div>

              {/* Card Footer Controls */}
              <div className="vs-scan-card__footer">
                <div className="vs-scan-card__primary-actions">
                  <Button className="vs-scan-card-button vs-scan-card-button--logs" variant="outline" size="sm" leftIcon={<Terminal size={15} />} onClick={() => setSelectedScan(scan)}>
                    Logs & Console
                  </Button>
                  {onViewReport && (
                    <Button className="vs-scan-card-button vs-scan-card-button--report" variant="outline" size="sm" leftIcon={<FileText size={15} />} onClick={() => onViewReport(scan.id)}>
                      View Report
                    </Button>
                  )}
                </div>

                <div className="vs-scan-card__actions">
                  {scan.status === 'running' && (
                    <Button
                      className="vs-scan-icon-action vs-scan-icon-action--stop"
                      variant="ghost"
                      size="sm"
                      onClick={() => setStopTargetScan(scan)}
                      title="Abort scan"
                      aria-label={`Abort scan ${scan.name}`}
                    >
                      <Square size={16} />
                    </Button>
                  )}
                  {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                    <Button
                      className="vs-scan-icon-action vs-scan-icon-action--rerun"
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRerun(scan)}
                      title="Re-run scan"
                      aria-label={`Re-run scan ${scan.name}`}
                    >
                      <RotateCw size={16} />
                    </Button>
                  )}
                  <Button
                    className="vs-scan-icon-action vs-scan-icon-action--delete"
                    variant="ghost"
                    size="sm"
                    disabled={scan.status === 'running'}
                    onClick={() => setDeleteTargetScan(scan)}
                    title={scan.status === 'running' ? 'Cannot delete running scan. Abort first.' : 'Delete record'}
                    aria-label={`Delete scan ${scan.name}`}
                  >
                    <Trash2 size={16} />
                  </Button>
                </div>
              </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* Table View */
        <div className="vs-scans-table-stage" style={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-lg)', overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                <th style={{ padding: '12px 16px' }}>Scan ID & Name</th>
                <th style={{ padding: '12px 16px' }}>Target URL</th>
                <th style={{ padding: '12px 16px' }}>Type</th>
                <th style={{ padding: '12px 16px' }}>Status</th>
                <th style={{ padding: '12px 16px', minWidth: '160px' }}>Progress</th>
                <th style={{ padding: '12px 16px' }}>Findings</th>
                <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.map((scan) => (
                <tr
                  key={scan.id}
                  style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}
                >
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{scan.name}</span>
                      <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)' }}>{scan.id}</span>
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {scan.targetUrl}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Badge variant="info" size="sm">{scan.type}</Badge>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <StatusBadge status={scan.status} size="sm" />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <ProgressBar
                      value={scan.progress}
                      variant={scan.status === 'running' ? 'primary' : 'low'}
                      size="sm"
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      {scan.findings.critical > 0 && (
                        <span className="vs-findings-pill vs-findings-pill--crit">{scan.findings.critical}</span>
                      )}
                      {scan.findings.high > 0 && (
                        <span className="vs-findings-pill vs-findings-pill--high">{scan.findings.high}</span>
                      )}
                      {scan.findings.medium > 0 && (
                        <span className="vs-findings-pill vs-findings-pill--med">{scan.findings.medium}</span>
                      )}
                      {scan.findings.total === 0 && <span style={{ color: 'var(--color-text-muted)' }}>0</span>}
                    </div>
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '6px' }}>
                      <Button
                        className="vs-scan-card-button vs-scan-card-button--logs"
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedScan(scan)}
                      >
                        Logs
                      </Button>
                      {onViewReport && (
                        <Button className="vs-scan-card-button vs-scan-card-button--report" variant="outline" size="sm" onClick={() => onViewReport(scan.id)}>
                          Report
                        </Button>
                      )}
                      {scan.status === 'running' && (
                        <Button
                          className="vs-scan-icon-action vs-scan-icon-action--stop"
                          variant="ghost"
                          size="sm"
                          title="Abort scan"
                          aria-label={`Abort scan ${scan.name}`}
                          onClick={() => setStopTargetScan(scan)}
                        >
                          <Square size={16} />
                        </Button>
                      )}
                      {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                        <Button
                          className="vs-scan-icon-action vs-scan-icon-action--rerun"
                          variant="ghost"
                          size="sm"
                          title="Re-run scan"
                          aria-label={`Re-run scan ${scan.name}`}
                          onClick={() => handleRerun(scan)}
                        >
                          <RotateCw size={16} />
                        </Button>
                      )}
                      <Button
                        className="vs-scan-icon-action vs-scan-icon-action--delete"
                        variant="ghost"
                        size="sm"
                        disabled={scan.status === 'running'}
                        title={scan.status === 'running' ? 'Cannot delete running scan. Abort first.' : 'Delete record'}
                        aria-label={`Delete scan ${scan.name}`}
                        onClick={() => setDeleteTargetScan(scan)}
                      >
                        <Trash2 size={16} />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Confirmation Modal: Abort / Stop Scan */}
      <Modal
        isOpen={!!stopTargetScan}
        onClose={() => !isAborting && setStopTargetScan(null)}
        size="sm"
        title="Abort Active Scan Pipeline"
        footer={
          <>
            <Button variant="ghost" onClick={() => setStopTargetScan(null)} disabled={isAborting}>
              Cancel
            </Button>
            <Button variant="danger" leftIcon={<Square size={14} />} isLoading={isAborting} onClick={confirmStop}>
              Abort Scan
            </Button>
          </>
        }
      >
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Are you sure you want to abort the active scan against{' '}
          <strong style={{ color: 'var(--color-text-primary)' }}>{stopTargetScan?.targetUrl}</strong>?
          The backend Nmap subprocess will be terminated immediately.
        </p>
      </Modal>

      {/* Confirmation Modal: Delete Scan Record */}
      <Modal
        isOpen={!!deleteTargetScan}
        onClose={() => !isDeleting && setDeleteTargetScan(null)}
        size="sm"
        title="Delete Scan Record"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteTargetScan(null)} disabled={isDeleting}>
              Cancel
            </Button>
            <Button variant="danger" leftIcon={<Trash2 size={14} />} isLoading={isDeleting} onClick={confirmDelete}>
              Delete Record
            </Button>
          </>
        }
      >
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Are you sure you want to permanently delete{' '}
          <strong style={{ color: 'var(--color-text-primary)' }}>{deleteTargetScan?.name}</strong> ({deleteTargetScan?.id})?
          This action will permanently delete the scan record and all associated discovery records from the PostgreSQL database.
        </p>
      </Modal>

      {/* Scan Detail / Terminal Log Modal */}
      {selectedScan && (
        <Modal
          isOpen={!!selectedScan}
          onClose={() => setSelectedScan(null)}
          size="lg"
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={18} color="var(--color-brand)" />
              <span>{selectedScan.id} — Execution Telemetry & Logs</span>
            </div>
          }
          footer={
            <>
              <Button variant="ghost" onClick={() => setSelectedScan(null)}>
                Close
              </Button>
              {onViewReport && (
                <Button
                  variant="outline"
                  leftIcon={<FileText size={14} />}
                  onClick={() => {
                    onViewReport(selectedScan.id);
                    setSelectedScan(null);
                  }}
                >
                  View Report
                </Button>
              )}
              {selectedScan.status === 'running' ? (
                <Button
                  variant="danger"
                  leftIcon={<Square size={14} />}
                  onClick={() => {
                    const toStop = selectedScan;
                    setSelectedScan(null);
                    setStopTargetScan(toStop);
                  }}
                >
                  Abort Scan
                </Button>
              ) : (
                <Button
                  variant="primary"
                  leftIcon={<RotateCw size={14} />}
                  onClick={() => {
                    handleRerun(selectedScan);
                    setSelectedScan(null);
                  }}
                >
                  Re-Execute Pipeline
                </Button>
              )}
            </>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  {selectedScan.name}
                </h3>
                <span style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)' }}>
                  {selectedScan.targetUrl}
                </span>
              </div>
              <StatusBadge status={selectedScan.status} size="md" />
            </div>

            <ProgressBar
              value={selectedScan.progress}
              variant={
                selectedScan.status === 'failed'
                  ? 'critical'
                  : selectedScan.status === 'completed'
                    ? 'low'
                    : 'primary'
              }
              animated={selectedScan.status === 'running'}
              label="Pipeline Completion"
            />

            {selectedScan.errorMessage && (
              <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', padding: '12px 16px', color: '#f87171', fontSize: '0.8125rem' }}>
                <strong style={{ fontWeight: 700 }}>Execution Error:</strong> {selectedScan.errorMessage}
              </div>
            )}

            {/* Genuine Nmap Process Telemetry & Execution Parameters */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Terminal size={14} /> Execution Telemetry & Parameters
                </span>
                <span style={{ fontSize: '0.6875rem', color: selectedScan.status === 'running' ? 'var(--color-low)' : 'var(--color-text-muted)' }}>
                  {selectedScan.status === 'running' ? '● Engine Running' : `Status: ${selectedScan.status.toUpperCase()}`}
                </span>
              </div>
              <div className="vs-terminal-box">
                <div className="vs-terminal-line" style={{ color: 'var(--color-brand-light)', fontWeight: 600 }}>
                  $ {getNmapCommandString(selectedScan.type, selectedScan.targetUrl)}
                </div>
                <div className="vs-terminal-line">
                  [TARGET] {selectedScan.targetUrl} | Profile: {selectedScan.type.toUpperCase()}
                </div>
                <div className="vs-terminal-line">
                  [TIMELINE] Started: {selectedScan.startedAt || 'Queued'} | Completed: {selectedScan.completedAt || (selectedScan.status === 'running' ? 'Active' : '—')} | Elapsed: {selectedScan.duration || (selectedScan.status === 'running' ? 'In progress' : '0s')}
                </div>
                <div className={`vs-terminal-line ${selectedScan.status === 'failed' ? 'vs-terminal-line--crit' : selectedScan.status === 'cancelled' ? 'vs-terminal-line--warn' : selectedScan.status === 'completed' ? 'vs-terminal-line--success' : ''}`}>
                  [STATE] {selectedScan.status.toUpperCase()} — {
                    selectedScan.status === 'completed'
                      ? 'Process exit code 0 (XML output parsed and results persisted)'
                      : selectedScan.status === 'cancelled'
                        ? 'Process terminated (Cancelled by operator)'
                        : selectedScan.status === 'failed'
                          ? `Process failed: ${selectedScan.errorMessage || 'Execution error'}`
                          : selectedScan.status === 'running'
                            ? 'Subprocess active under process pool manager'
                            : 'Scan queued in worker pool'
                  }
                </div>
                <div className="vs-terminal-line" style={{ color: 'var(--color-text-muted)', fontSize: '0.6875rem', marginTop: '6px', borderTop: '1px dashed rgba(255,255,255,0.1)', paddingTop: '6px' }}>
                  [TELEMETRY NOTE] Real-time stdout/stderr console streaming is not retained by the backend service. Raw discovery findings are parsed directly from Nmap XML into the persistent database and presented in the Discovered Ports & Services table below.
                </div>
              </div>
            </div>

            {/* Discovered Services & Open Ports (Raw Nmap Discovery) */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  Discovered Ports & Services ({scanResults.length})
                </span>
                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', background: 'var(--color-bg-surface)', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--color-border)' }}>
                  Service Discovery — Informational (Not Confirmed Vulnerabilities)
                </span>
              </div>

              {loadingResults ? (
                <div style={{ padding: '20px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '0.8125rem', background: 'var(--color-bg-surface)', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
                  Fetching discovery records from PostgreSQL...
                </div>
              ) : resultsError ? (
                <div style={{ padding: '14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', color: '#f87171', fontSize: '0.8125rem' }}>
                  {resultsError}
                </div>
              ) : scanResults.length === 0 ? (
                <div style={{ padding: '20px', textAlign: 'center', background: 'var(--color-bg-surface)', borderRadius: '8px', border: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                  {selectedScan.status === 'completed'
                    ? 'No open ports or services discovered on this target.'
                    : selectedScan.status === 'running'
                      ? 'Scan in progress. Discovered ports will appear once Nmap finishes.'
                      : selectedScan.status === 'queued'
                        ? 'Scan queued for execution.'
                        : selectedScan.status === 'failed'
                          ? 'Scan failed before results could be recorded.'
                          : 'No scan results available.'}
                </div>
              ) : (
                <div style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '8px', overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--color-border)', background: 'rgba(255,255,255,0.02)', textAlign: 'left', color: 'var(--color-text-muted)' }}>
                        <th style={{ padding: '8px 12px' }}>Host</th>
                        <th style={{ padding: '8px 12px' }}>Port</th>
                        <th style={{ padding: '8px 12px' }}>Protocol</th>
                        <th style={{ padding: '8px 12px' }}>State</th>
                        <th style={{ padding: '8px 12px' }}>Service</th>
                        <th style={{ padding: '8px 12px' }}>Product / Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResults.map((r) => (
                        <tr key={r.id} style={{ borderBottom: '1px solid var(--color-border)' }}>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)' }}>
                            {r.host_address}{(r.hostname || r.host_name) ? ` (${r.hostname || r.host_name})` : ''}
                          </td>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                            {r.port ?? '—'}
                          </td>
                          <td style={{ padding: '8px 12px', textTransform: 'uppercase' }}>
                            {r.protocol || 'tcp'}
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <span style={{
                              padding: '2px 6px',
                              borderRadius: '4px',
                              fontWeight: 600,
                              fontSize: '0.6875rem',
                              background: r.port_state === 'open' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(156, 163, 175, 0.15)',
                              color: r.port_state === 'open' ? '#4ade80' : 'var(--color-text-muted)',
                            }}>
                              {r.port_state || r.host_state || 'unknown'}
                            </span>
                          </td>
                          <td style={{ padding: '8px 12px', color: 'var(--color-text-primary)' }}>
                            {r.service_name || 'unknown'}
                          </td>
                          <td style={{ padding: '8px 12px', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.6875rem' }}>
                            {[r.service_product, r.service_version, r.service_extra_info].filter(Boolean).join(' ') || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Findings Breakdown Notice */}
            <div style={{ background: 'var(--color-bg-surface)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                  Vulnerability Findings:
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginLeft: '8px' }}>
                  (Port discovery only — unconfirmed CVEs are not fabricated)
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <span className="vs-findings-pill vs-findings-pill--crit">{selectedScan.findings.critical} Critical</span>
                <span className="vs-findings-pill vs-findings-pill--high">{selectedScan.findings.high} High</span>
                <span className="vs-findings-pill vs-findings-pill--med">{selectedScan.findings.medium} Medium</span>
                <span className="vs-findings-pill vs-findings-pill--low">{selectedScan.findings.low} Low</span>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default ScansPage;
