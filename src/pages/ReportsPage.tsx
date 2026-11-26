/**
 * Phase 9: Security Reports & Export (Phases 9.1, 9.2, 9.3)
 *
 * - Security posture summary from real backend dashboard API data.
 * - Report archive persisted in PostgreSQL via /api/v1/reports (Phase 9.2).
 * - CSV export: real local file download with OWASP formula-injection protection (Phase 9.1).
 * - PDF export: real binary PDF generation with jsPDF (Phase 9.3).
 * - Report generation: persists to PostgreSQL with snapshot telemetry.
 * - Delete reports from persistent archive.
 * - Empty/loading/error states for both posture panel and report archive.
 */

import React, { useState, useCallback } from 'react';
import { useAsync } from '../hooks/useAsync';
import {
  getDashboard,
  getReports,
  getReport,
  generateReport,
  deleteReport,
  exportReportCsv,
} from '../services/api';
import { exportReportPdf } from '../services/pdfExport';
import type { Report } from '../types';
import { StateView } from '../components/ui/StateView';
import { StatCard } from '../components/ui/StatCard';
import { Button } from '../components/ui/Button';
import { SearchInput, Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { useToast } from '../components/ui/Toast';
import {
  FileText, Download, Plus, RefreshCw, Eye, Trash2,
  FileDown, FileCog, CheckCircle, Clock, AlertCircle, Info,
  Shield, AlertTriangle, Database, Activity,
} from 'lucide-react';

// ─── Config ───────────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { bg: string; text: string; icon: React.ElementType }> = {
  ready: { bg: 'rgba(34,197,94,0.12)', text: '#86efac', icon: CheckCircle },
  generating: { bg: 'rgba(59,130,246,0.12)', text: '#93c5fd', icon: Clock },
  failed: { bg: 'rgba(239,68,68,0.12)', text: '#fca5a5', icon: AlertCircle },
};

const TYPE_COLORS: Record<string, string> = {
  executive: 'rgba(168,85,247,0.15)',
  technical: 'rgba(59,130,246,0.15)',
  compliance: 'rgba(234,179,8,0.15)',
  network: 'rgba(20,184,166,0.15)',
  delta: 'rgba(20,184,166,0.15)',
};

const TYPE_ACCENT: Record<string, string> = {
  executive: '#c084fc',
  technical: '#60a5fa',
  compliance: '#fbbf24',
  network: '#2dd4bf',
  delta: '#2dd4bf',
};

const TODAY = new Date().toISOString().split('T')[0];
const THIRTY_DAYS_AGO = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
  .toISOString()
  .split('T')[0];

// ─── Sub-components ───────────────────────────────────────────────────────────

interface SeverityBarProps {
  label: string;
  count: number;
  total: number;
  color: string;
}

const SeverityBar: React.FC<SeverityBarProps> = ({ label, count, total, color }) => {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
      <span style={{ width: '56px', fontSize: '0.75rem', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
        {label}
      </span>
      <div style={{ flex: 1, height: '6px', borderRadius: '3px', background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            width: `${pct}%`,
            background: color,
            borderRadius: '3px',
            transition: 'width 0.6s cubic-bezier(0.4,0,0.2,1)',
          }}
        />
      </div>
      <span style={{ fontSize: '0.8125rem', fontWeight: 700, minWidth: '28px', textAlign: 'right', color }}>
        {count}
      </span>
    </div>
  );
};

// ─── Main Component ───────────────────────────────────────────────────────────

export const ReportsPage: React.FC = () => {
  const { showToast } = useToast();

  // Live security posture data from backend
  const { data: dashData, state: dashState, error: dashError, refetch: refetchDash, isRefreshing: dashRefreshing, isStale: dashStale, lastUpdated: dashUpdated } = useAsync(getDashboard);

  // Persistent report archive from PostgreSQL backend API
  const {
    data: apiReports,
    state: reportsState,
    error: reportsError,
    refetch: refetchReports,
    isRefreshing: reportsRefreshing,
    isStale: reportsStale,
    lastUpdated: reportsUpdated,
  } = useAsync((signal) => getReports(undefined, signal));

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [isGenOpen, setIsGenOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [deletingReportId, setDeletingReportId] = useState<string | null>(null);
  const [viewReport, setViewReport] = useState<Report | null>(null);
  const [form, setForm] = useState({
    name: '',
    target: '',
    type: 'executive' as Report['type'],
    format: 'pdf' as 'pdf' | 'csv',
    dateFrom: THIRTY_DAYS_AGO,
    dateTo: TODAY,
  });

  const [snapshotTime] = useState<string>(() => new Date().toLocaleString());

  const refetch = useCallback(() => {
    refetchDash();
    refetchReports();
  }, [refetchDash, refetchReports]);

  const allReports: Report[] = apiReports || [];

  const filtered = allReports.filter((r) => {
    const matchType = typeFilter === 'all' || r.type === typeFilter;
    const q = search.toLowerCase();
    const matchSearch = r.name.toLowerCase().includes(q) || r.target.toLowerCase().includes(q);
    return matchType && matchSearch;
  });

  const resetFilters = () => { setTypeFilter('all'); setSearch(''); };
  const hasFilters = typeFilter !== 'all' || search.trim() !== '';

  const readyCount = allReports.filter((r) => r.status === 'ready').length;
  const generatingCount = allReports.filter((r) => r.status === 'generating').length;

  // Posture KPIs from real backend data
  const stats = dashData?.stats;
  const totalAssets = stats?.totalAssets ?? 0;
  const totalScans = stats?.totalScans ?? 0;
  const activeScans = stats?.activeScans ?? 0;
  const totalVulns = stats?.totalVulnerabilities ?? 0;
  const criticalCount = stats?.criticalCount ?? 0;
  const highCount = stats?.highCount ?? 0;
  const mediumCount = stats?.mediumCount ?? 0;
  const lowCount = stats?.lowCount ?? 0;
  const securityScore = stats?.securityScore ?? null;

  // ─── Handlers ─────────────────────────────────────────────────────────────

  const handleGenerate = async () => {
    if (!form.name.trim()) {
      showToast('error', 'Report name is required.');
      return;
    }
    if (!form.target.trim()) {
      showToast('error', 'Target scope is required.');
      return;
    }
    if (form.dateFrom && form.dateTo && form.dateFrom > form.dateTo) {
      showToast('error', 'Date From must be on or before Date To.');
      return;
    }

    setIsGenerating(true);
    try {
      const r = await generateReport({
        name: form.name.trim(),
        target: form.target.trim(),
        type: form.type,
        format: form.format,
        dateFrom: form.dateFrom,
        dateTo: form.dateTo,
      });
      refetchReports();
      setIsGenOpen(false);
      setForm({ name: '', target: '', type: 'executive', format: 'pdf', dateFrom: THIRTY_DAYS_AGO, dateTo: TODAY });
      showToast('success', `Report "${r.name}" successfully generated and saved to PostgreSQL.`);
    } catch (err: unknown) {
      showToast('error', err instanceof Error ? err.message : 'Failed to save report. Check backend connectivity.');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleOpenReport = async (report: Report) => {
    setViewReport(report);
    try {
      const detailed = await getReport(report.id);
      if (detailed) {
        setViewReport(detailed);
      }
    } catch (err: unknown) {
      showToast('warning', err instanceof Error ? `Report details unavailable: ${err.message}` : 'Report details are unavailable.');
    }
  };

  const handleDeleteReport = async (reportId: string, reportName: string) => {
    if (!window.confirm(`Delete saved report "${reportName}"? This action cannot be undone.`)) {
      return;
    }
    setDeletingReportId(reportId);
    try {
      await deleteReport(reportId);
      refetchReports();
      if (viewReport?.id === reportId) {
        setViewReport(null);
      }
      showToast('info', `Report "${reportName}" deleted from archive.`);
    } catch (err: unknown) {
      showToast('error', err instanceof Error ? err.message : 'Failed to delete report.');
    } finally {
      setDeletingReportId(null);
    }
  };

  const handleExport = async (report: Report, format: 'pdf' | 'csv') => {
    if (format === 'csv') {
      try {
        exportReportCsv(report);
        showToast(
          'success',
          `"${report.name}" exported as CSV \u2014 formula-injection sanitization applied.`
        );
      } catch (err: any) {
        showToast('error', `CSV export failed: ${err?.message || 'Unknown error'}`);
      }
    } else {
      try {
        // If the report doesn't have detailed snapshot data, fetch it from backend to get findings
        let targetReport = report;
        if (!targetReport.snapshotData && targetReport.id) {
          try {
            const detailed = await getReport(targetReport.id);
            if (detailed) {
              targetReport = detailed;
            }
          } catch {
            // Proceed with summary report if detailed lookup fails
          }
        }

        const result = exportReportPdf(targetReport);
        showToast(
          'success',
          `"${report.name}" downloaded as PDF (${result.filename}).`
        );
      } catch (err: any) {
        showToast('error', `PDF export failed: ${err?.message || 'Unknown error'}`);
      }
    }
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div
      className="animate-fade-in"
      style={{
        padding: 'clamp(16px, 3vw, 24px)',
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        maxWidth: '1600px',
        margin: '0 auto',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.01em' }}>
            Security Reports
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
            Generate and export security assessment reports. CSV exports are real file downloads;
            PDF export generates a real downloadable document from confirmed report data.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <Button variant="outline" size="sm" leftIcon={<RefreshCw size={14} />} onClick={refetch} isLoading={dashRefreshing || reportsRefreshing}>
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            leftIcon={<Plus size={14} />}
            onClick={() => setIsGenOpen(true)}
          >
            Generate Report
          </Button>
        </div>
      </div>

      {/* Live Security Posture Summary */}
      <div
        style={{
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: '16px',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '14px 20px',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(59,130,246,0.04)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} color="var(--color-brand-light)" />
            <span style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>
              Live Security Posture
            </span>
            <span
              style={{
                fontSize: '0.6875rem',
                padding: '2px 8px',
                borderRadius: '20px',
                background: 'rgba(59,130,246,0.12)',
                color: '#93c5fd',
                fontWeight: 600,
              }}
            >
              REAL-TIME BACKEND DATA
            </span>
          </div>
          {securityScore !== null && dashState === 'success' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                Security Score
              </span>
              <span
                style={{
                  fontSize: '1.25rem',
                  fontWeight: 900,
                  color:
                    securityScore >= 70
                      ? '#86efac'
                      : securityScore >= 40
                        ? '#fbbf24'
                        : '#fca5a5',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {securityScore}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>/100</span>
            </div>
          )}
        </div>

        <div style={{ padding: '20px' }}>
          {dashStale && (
            <div role="alert" style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 12px', marginBottom: '14px', borderRadius: '8px', background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.3)', color: 'var(--color-warning)', fontSize: '0.8125rem' }}>
              <span>Showing the last successful posture snapshot. {dashError || 'Refresh failed.'}{dashUpdated ? ` Last updated ${new Date(dashUpdated).toLocaleTimeString()}.` : ''}</span>
              <Button variant="ghost" size="sm" onClick={refetchDash} isLoading={dashRefreshing}>Retry</Button>
            </div>
          )}
          {dashState === 'loading' || dashState === 'idle' ? (
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  style={{
                    flex: '1 1 160px',
                    height: '72px',
                    borderRadius: '10px',
                    background: 'rgba(255,255,255,0.04)',
                    animation: 'pulse 2s ease-in-out infinite',
                  }}
                />
              ))}
            </div>
          ) : dashState === 'error' || !dashData ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '14px 16px',
                background: 'rgba(239,68,68,0.06)',
                borderRadius: '10px',
                border: '1px solid rgba(239,68,68,0.2)',
              }}
            >
              <AlertTriangle size={16} color="#fca5a5" />
              <p style={{ fontSize: '0.8125rem', color: '#fca5a5', margin: 0 }}>
                Backend telemetry is unreachable. Security posture metrics are unavailable.
              </p>
              <Button
                variant="ghost"
                size="sm"
                onClick={refetchDash}
                style={{ marginLeft: 'auto' }}
              >
                Retry
              </Button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* KPI Row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '12px' }}>
                {[
                  { label: 'Registered Assets', value: totalAssets, icon: <Database size={15} color="#93c5fd" />, bg: 'rgba(59,130,246,0.08)' },
                  { label: 'Total Scans', value: totalScans, icon: <Activity size={15} color="#86efac" />, bg: 'rgba(34,197,94,0.08)' },
                  { label: 'Active Scans', value: activeScans, icon: <Clock size={15} color="#fbbf24" />, bg: 'rgba(234,179,8,0.08)' },
                  { label: 'Total Vulnerabilities', value: totalVulns, icon: <AlertCircle size={15} color="#fca5a5" />, bg: 'rgba(239,68,68,0.08)' },
                ].map(({ label, value, icon, bg }) => (
                  <div
                    key={label}
                    style={{
                      background: bg,
                      borderRadius: '10px',
                      padding: '14px',
                      border: '1px solid rgba(255,255,255,0.06)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                      {icon}
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          color: 'var(--color-text-muted)',
                          fontWeight: 600,
                          textTransform: 'uppercase',
                          letterSpacing: '0.03em',
                        }}
                      >
                        {label}
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: '1.375rem',
                        fontWeight: 900,
                        color: 'var(--color-text-primary)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {value}
                    </span>
                  </div>
                ))}
              </div>

              {/* Severity breakdown */}
              {totalVulns === 0 ? (
                <div
                  style={{
                    padding: '16px',
                    background: 'rgba(34,197,94,0.06)',
                    borderRadius: '10px',
                    border: '1px solid rgba(34,197,94,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                  }}
                >
                  <CheckCircle size={16} color="#86efac" />
                  <span style={{ fontSize: '0.8125rem', color: '#86efac', fontWeight: 600 }}>
                    No vulnerability findings in the database. All clear.
                  </span>
                </div>
              ) : (
                <div>
                  <span
                    style={{
                      fontSize: '0.6875rem',
                      color: 'var(--color-text-muted)',
                      display: 'block',
                      marginBottom: '10px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      fontWeight: 600,
                    }}
                  >
                    Vulnerability Severity Distribution &mdash; {totalVulns} confirmed findings
                  </span>
                  <SeverityBar label="Critical" count={criticalCount} total={totalVulns} color="#ef4444" />
                  <SeverityBar label="High" count={highCount} total={totalVulns} color="#f97316" />
                  <SeverityBar label="Medium" count={mediumCount} total={totalVulns} color="#eab308" />
                  <SeverityBar label="Low" count={lowCount} total={totalVulns} color="#22c55e" />
                </div>
              )}

              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', margin: 0 }}>
                Posture summary reflects live database state at{' '}
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)' }}>
                  {snapshotTime}
                </span>
                . Open ports discovered by Nmap are not classified as confirmed vulnerabilities.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Archive KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '16px' }}>
        <StatCard label="Total Reports" value={allReports.length} subtitle="In archive" accent="brand" />
        <StatCard label="Ready to Download" value={readyCount} subtitle="CSV available" accent="low" />
        <StatCard label="Generating" value={generatingCount} subtitle="Processing queue" accent="medium" />
        <StatCard label="Report Types" value={4} subtitle="Exec, Tech, Compliance, Delta" accent="high" />
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        {['all', 'executive', 'technical', 'compliance', 'network', 'delta'].map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTypeFilter(t)}
            aria-pressed={typeFilter === t}
            style={{
              padding: '6px 14px',
              borderRadius: '20px',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
              border: typeFilter === t ? '1px solid var(--color-brand)' : '1px solid var(--color-border)',
              backgroundColor:
                typeFilter === t ? 'var(--color-brand-subtle)' : 'var(--color-bg-surface)',
              color:
                typeFilter === t ? 'var(--color-brand-light)' : 'var(--color-text-secondary)',
              transition: 'all 0.15s ease',
              textTransform: 'capitalize',
            }}
          >
            {t === 'all' ? 'All Types' : t}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', minWidth: '200px', flex: 1, maxWidth: '360px' }}>
          <SearchInput value={search} onChange={setSearch} placeholder="Search reports..." />
        </div>
      </div>

      {/* Report Cards */}
      <StateView
        state={reportsState}
        error={reportsError}
        onRetry={refetchReports}
        isRefreshing={reportsRefreshing}
        isStale={reportsStale}
        staleError={reportsError}
        lastUpdated={reportsUpdated}
        loadingMessage="Loading report archive..."
        isEmpty={filtered.length === 0}
        emptyMessage={
          hasFilters ? 'No reports match filter criteria' : 'No security reports in archive'
        }
        emptySubtitle={
          hasFilters
            ? 'Adjust your type filter or search query.'
            : 'Generate your first comprehensive security audit report.'
        }
        emptyAction={
          hasFilters ? (
            <Button variant="outline" size="sm" onClick={resetFilters}>
              Reset Filters
            </Button>
          ) : (
            <Button
              variant="primary"
              size="sm"
              leftIcon={<Plus size={14} />}
              onClick={() => setIsGenOpen(true)}
            >
              Generate First Report
            </Button>
          )
        }
      >
        <div
          style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '16px' }}
        >
          {filtered.map((report) => {
            const sc = STATUS_CONFIG[report.status] ?? STATUS_CONFIG.generating;
            const StatusIcon = sc.icon;
            const typeColor = TYPE_COLORS[report.type] || 'rgba(59,130,246,0.15)';
            const accent = TYPE_ACCENT[report.type] || '#60a5fa';
            return (
              <div
                key={report.id}
                style={{
                  background: 'var(--color-bg-card)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '16px',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column',
                  transition: 'border-color 0.2s, transform 0.2s, box-shadow 0.2s',
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = `${accent}55`;
                  (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)';
                  (e.currentTarget as HTMLElement).style.boxShadow =
                    '0 8px 24px rgba(0,0,0,0.3)';
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.borderColor = 'var(--color-border)';
                  (e.currentTarget as HTMLElement).style.transform = 'none';
                  (e.currentTarget as HTMLElement).style.boxShadow = 'none';
                }}
              >
                <div
                  style={{
                    height: '3px',
                    background: `linear-gradient(90deg, ${accent}88, ${accent}22)`,
                  }}
                />
                <div
                  style={{
                    padding: '20px',
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                  }}
                >
                  {/* Title row */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div
                        style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '9px',
                          background: typeColor,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0,
                        }}
                      >
                        <FileText size={18} color={accent} />
                      </div>
                      <div>
                        <h4
                          style={{
                            fontSize: '0.875rem',
                            fontWeight: 700,
                            color: 'var(--color-text-primary)',
                            margin: 0,
                          }}
                        >
                          {report.name}
                        </h4>
                        <span
                          style={{
                            fontSize: '0.6875rem',
                            color: 'var(--color-text-muted)',
                            textTransform: 'capitalize',
                          }}
                        >
                          {report.type} report
                        </span>
                      </div>
                    </div>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '3px 8px',
                        borderRadius: '12px',
                        background: sc.bg,
                        flexShrink: 0,
                        marginLeft: '8px',
                      }}
                    >
                      <StatusIcon size={11} color={sc.text} />
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          fontWeight: 700,
                          color: sc.text,
                          textTransform: 'capitalize',
                        }}
                      >
                        {report.status}
                      </span>
                    </div>
                  </div>

                  {/* Meta */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div
                      style={{
                        background: 'var(--color-bg-surface)',
                        borderRadius: '8px',
                        padding: '10px',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      <span
                        style={{
                          fontSize: '0.625rem',
                          color: 'var(--color-text-muted)',
                          display: 'block',
                          marginBottom: '2px',
                          textTransform: 'uppercase',
                        }}
                      >
                        Target Scope
                      </span>
                      <span
                        style={{
                          fontSize: '0.8125rem',
                          fontWeight: 500,
                          color: 'var(--color-text-primary)',
                        }}
                      >
                        {report.target}
                      </span>
                    </div>
                    <div
                      style={{
                        background: 'var(--color-bg-surface)',
                        borderRadius: '8px',
                        padding: '10px',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      <span
                        style={{
                          fontSize: '0.625rem',
                          color: 'var(--color-text-muted)',
                          display: 'block',
                          marginBottom: '2px',
                          textTransform: 'uppercase',
                        }}
                      >
                        Scan Date
                      </span>
                      <span
                        style={{
                          fontSize: '0.8125rem',
                          fontWeight: 500,
                          color: 'var(--color-text-primary)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {report.scanDate}
                      </span>
                    </div>
                  </div>

                  {/* Severity summary chips */}
                  <div>
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        color: 'var(--color-text-muted)',
                        display: 'block',
                        marginBottom: '6px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      Findings Summary
                    </span>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      {[
                        { label: 'C', count: report.findingsSummary.critical, color: '#fca5a5', bg: 'rgba(239,68,68,0.12)' },
                        { label: 'H', count: report.findingsSummary.high, color: '#fdba74', bg: 'rgba(249,115,22,0.12)' },
                        { label: 'M', count: report.findingsSummary.medium, color: '#fde047', bg: 'rgba(234,179,8,0.12)' },
                        { label: 'L', count: report.findingsSummary.low, color: '#86efac', bg: 'rgba(34,197,94,0.12)' },
                      ].map(({ label, count, color, bg }) => (
                        <div
                          key={label}
                          style={{
                            flex: 1,
                            background: bg,
                            borderRadius: '6px',
                            padding: '6px',
                            textAlign: 'center',
                          }}
                        >
                          <div style={{ fontSize: '1rem', fontWeight: 800, color }}>{count}</div>
                          <div style={{ fontSize: '0.5625rem', color, opacity: 0.7, fontWeight: 600 }}>
                            {label === 'C'
                              ? 'CRIT'
                              : label === 'H'
                                ? 'HIGH'
                                : label === 'M'
                                  ? 'MED'
                                  : 'LOW'}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Card footer */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border)',
                    }}
                  >
                    <div>
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          background: 'rgba(255,255,255,0.05)',
                          color: 'var(--color-text-muted)',
                          fontFamily: 'var(--font-mono)',
                          textTransform: 'uppercase',
                        }}
                      >
                        {report.format}
                      </span>
                      {report.fileSize && report.fileSize !== 'Pending...' && (
                        <span
                          style={{
                            fontSize: '0.6875rem',
                            color: 'var(--color-text-muted)',
                            marginLeft: '8px',
                          }}
                        >
                          {report.fileSize}
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        leftIcon={<Eye size={12} />}
                        onClick={() => handleOpenReport(report)}
                      >
                        View
                      </Button>
                      {report.status === 'ready' && (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            leftIcon={<FileCog size={12} />}
                            onClick={() => handleExport(report, 'csv')}
                          >
                            CSV
                          </Button>
                          <Button
                            variant="primary"
                            size="sm"
                            leftIcon={<FileDown size={12} />}
                            onClick={() => handleExport(report, 'pdf')}
                          >
                            PDF
                          </Button>
                        </>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        leftIcon={<Trash2 size={12} color="#fca5a5" />}
                        onClick={() => handleDeleteReport(report.id, report.name)}
                        disabled={deletingReportId !== null}
                        isLoading={deletingReportId === report.id}
                        title="Delete report"
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </StateView>

      {/* Generate Report Modal */}
      <Modal
        isOpen={isGenOpen}
        onClose={() => !isGenerating && setIsGenOpen(false)}
        title="Generate New Security Report"
        size="md"
        footer={
          <>
            <Button variant="ghost" disabled={isGenerating} onClick={() => setIsGenOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" isLoading={isGenerating} onClick={handleGenerate}>
              Generate
            </Button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <Input
            label="Report Name *"
            placeholder="e.g. Q4 Infrastructure Pentest Report"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <Input
            label="Target Scope *"
            placeholder="e.g. Production Cloud Infrastructure / All Assets"
            value={form.target}
            onChange={(e) => setForm({ ...form, target: e.target.value })}
          />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label
                style={{
                  fontSize: '0.8125rem',
                  fontWeight: 500,
                  color: 'var(--color-text-secondary)',
                  display: 'block',
                  marginBottom: '4px',
                }}
              >
                Report Type
              </label>
              <select
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value as Report['type'] })}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '10px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.875rem',
                  outline: 'none',
                }}
              >
                <option value="executive">Executive Summary</option>
                <option value="technical">Technical Report</option>
                <option value="compliance">Compliance Report</option>
                <option value="network">Network Scan Report</option>
                <option value="delta">Delta / Diff Report</option>
              </select>
            </div>
            <div>
              <label
                style={{
                  fontSize: '0.8125rem',
                  fontWeight: 500,
                  color: 'var(--color-text-secondary)',
                  display: 'block',
                  marginBottom: '4px',
                }}
              >
                Format
              </label>
              <select
                value={form.format}
                onChange={(e) => setForm({ ...form, format: e.target.value as 'pdf' | 'csv' })}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '10px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.875rem',
                  outline: 'none',
                }}
              >
                <option value="pdf">PDF Document (Real Download)</option>
                <option value="csv">CSV Spreadsheet (Real Download)</option>
              </select>
            </div>
          </div>
          {/* Date range */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label
                style={{
                  fontSize: '0.8125rem',
                  fontWeight: 500,
                  color: 'var(--color-text-secondary)',
                  display: 'block',
                  marginBottom: '4px',
                }}
              >
                Date From
              </label>
              <input
                type="date"
                value={form.dateFrom}
                max={TODAY}
                onChange={(e) => setForm({ ...form, dateFrom: e.target.value })}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '10px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.875rem',
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div>
              <label
                style={{
                  fontSize: '0.8125rem',
                  fontWeight: 500,
                  color: 'var(--color-text-secondary)',
                  display: 'block',
                  marginBottom: '4px',
                }}
              >
                Date To
              </label>
              <input
                type="date"
                value={form.dateTo}
                max={TODAY}
                onChange={(e) => setForm({ ...form, dateTo: e.target.value })}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  background: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '10px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.875rem',
                  outline: 'none',
                  boxSizing: 'border-box',
                }}
              />
            </div>
          </div>
          {/* Data-accuracy notice */}
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '8px',
              padding: '12px 14px',
              background: 'rgba(59,130,246,0.06)',
              borderRadius: '10px',
              border: '1px solid rgba(59,130,246,0.15)',
            }}
          >
            <Info size={14} color="#93c5fd" style={{ flexShrink: 0, marginTop: '1px' }} />
            <p style={{ fontSize: '0.8125rem', color: '#93c5fd', margin: 0, lineHeight: 1.5 }}>
              Findings summary reflects vulnerability counts from the live backend at generation
              time. Open ports discovered by Nmap are{' '}
              <strong>not</strong> counted as confirmed vulnerabilities.
            </p>
          </div>
        </div>
      </Modal>

      {/* View Report Modal */}
      <Modal
        isOpen={!!viewReport}
        onClose={() => setViewReport(null)}
        title={viewReport?.name || ''}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onClick={() => setViewReport(null)}>
              Close
            </Button>
            {viewReport?.status === 'ready' && (
              <>
                <Button
                  variant="outline"
                  leftIcon={<FileCog size={14} />}
                  onClick={() => {
                    handleExport(viewReport!, 'csv');
                    setViewReport(null);
                  }}
                >
                  Export CSV
                </Button>
                <Button
                  variant="primary"
                  leftIcon={<Download size={14} />}
                  onClick={() => {
                    handleExport(viewReport!, 'pdf');
                    setViewReport(null);
                  }}
                >
                  Export PDF
                </Button>
              </>
            )}
          </>
        }
      >
        {viewReport && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {/* Report metadata */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
              {[
                { label: 'Target Scope', val: viewReport.target },
                { label: 'Type', val: viewReport.type },
                { label: 'Scan Date', val: viewReport.scanDate },
                { label: 'Format', val: viewReport.format.toUpperCase() },
                { label: 'Status', val: viewReport.status },
                { label: 'File Size', val: viewReport.fileSize || 'Pending...' },
              ].map(({ label, val }) => (
                <div
                  key={label}
                  style={{
                    background: 'var(--color-bg-surface)',
                    borderRadius: '10px',
                    padding: '12px',
                    border: '1px solid var(--color-border)',
                  }}
                >
                  <span
                    style={{
                      fontSize: '0.6875rem',
                      color: 'var(--color-text-muted)',
                      display: 'block',
                      marginBottom: '2px',
                      textTransform: 'uppercase',
                    }}
                  >
                    {label}
                  </span>
                  <span
                    style={{
                      fontWeight: 600,
                      color: 'var(--color-text-primary)',
                      textTransform: 'capitalize',
                    }}
                  >
                    {val}
                  </span>
                </div>
              ))}
            </div>

            {/* Snapshot metadata if available */}
            {viewReport.snapshotData && (
              <div
                style={{
                  background: 'rgba(59,130,246,0.05)',
                  border: '1px solid rgba(59,130,246,0.15)',
                  borderRadius: '10px',
                  padding: '12px 16px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '8px',
                  }}
                >
                  <span
                    style={{
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      color: '#93c5fd',
                      textTransform: 'uppercase',
                    }}
                  >
                    Persisted PostgreSQL Snapshot
                  </span>
                  {viewReport.securityScore !== undefined && viewReport.securityScore !== null && (
                    <span style={{ fontSize: '0.8125rem', fontWeight: 800, color: '#86efac' }}>
                      Security Posture: {viewReport.securityScore}/100
                    </span>
                  )}
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                    gap: '8px',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    Assets Evaluated:{' '}
                    <strong style={{ color: 'var(--color-text-primary)' }}>
                      {viewReport.totalAssets ?? viewReport.snapshotData.total_assets ?? 0}
                    </strong>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    Scans In Scope:{' '}
                    <strong style={{ color: 'var(--color-text-primary)' }}>
                      {viewReport.totalScans ?? viewReport.snapshotData.total_scans ?? 0}
                    </strong>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    Report Code:{' '}
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)' }}>
                      {viewReport.reportCode || viewReport.id.slice(0, 12)}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Findings breakdown */}
            <div>
              <span
                style={{
                  fontSize: '0.6875rem',
                  color: 'var(--color-text-muted)',
                  display: 'block',
                  marginBottom: '10px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                Findings Breakdown
              </span>
              {viewReport.findingsSummary.total === 0 ? (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '12px 14px',
                    background: 'rgba(34,197,94,0.06)',
                    borderRadius: '10px',
                    border: '1px solid rgba(34,197,94,0.15)',
                  }}
                >
                  <CheckCircle size={14} color="#86efac" />
                  <span style={{ fontSize: '0.8125rem', color: '#86efac' }}>
                    No confirmed vulnerability findings for this report scope.
                  </span>
                </div>
              ) : (
                <>
                  {[
                    { label: 'Critical', count: viewReport.findingsSummary.critical, color: '#fca5a5' },
                    { label: 'High', count: viewReport.findingsSummary.high, color: '#fdba74' },
                    { label: 'Medium', count: viewReport.findingsSummary.medium, color: '#fde047' },
                    { label: 'Low', count: viewReport.findingsSummary.low, color: '#86efac' },
                    { label: 'Info', count: viewReport.findingsSummary.info, color: '#93c5fd' },
                  ].map(({ label, count, color }) => (
                    <div
                      key={label}
                      style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}
                    >
                      <span
                        style={{
                          width: '64px',
                          fontSize: '0.8125rem',
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        {label}
                      </span>
                      <div
                        style={{
                          flex: 1,
                          height: '8px',
                          borderRadius: '4px',
                          background: 'rgba(255,255,255,0.06)',
                          overflow: 'hidden',
                        }}
                      >
                        <div
                          style={{
                            height: '100%',
                            width: `${
                              viewReport.findingsSummary.total > 0
                                ? (count / viewReport.findingsSummary.total) * 100
                                : 0
                            }%`,
                            background: color,
                            borderRadius: '4px',
                            transition: 'width 0.5s ease',
                          }}
                        />
                      </div>
                      <span
                        style={{
                          fontSize: '0.875rem',
                          fontWeight: 700,
                          minWidth: '24px',
                          textAlign: 'right',
                          color,
                        }}
                      >
                        {count}
                      </span>
                    </div>
                  ))}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'flex-end',
                      marginTop: '6px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border)',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                      Total:{' '}
                      <strong style={{ color: 'var(--color-text-primary)' }}>
                        {viewReport.findingsSummary.total}
                      </strong>{' '}
                      confirmed findings
                    </span>
                  </div>
                </>
              )}
            </div>

            {/* Status-specific notices */}
            {viewReport.status === 'generating' && (
              <div
                style={{
                  textAlign: 'center',
                  padding: '20px',
                  background: 'rgba(59,130,246,0.06)',
                  borderRadius: '12px',
                  border: '1px solid rgba(59,130,246,0.2)',
                }}
              >
                <p style={{ color: '#93c5fd', fontSize: '0.875rem', margin: 0 }}>
                  &#x23F3; Report is still being generated. Check back in a moment.
                </p>
              </div>
            )}

            {viewReport.status === 'ready' && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  padding: '14px 16px',
                  background: 'rgba(34,197,94,0.06)',
                  borderRadius: '10px',
                  border: '1px solid rgba(34,197,94,0.2)',
                }}
              >
                <Info size={15} color="#86efac" style={{ flexShrink: 0, marginTop: '1px' }} />
                <p style={{ fontSize: '0.8125rem', color: '#86efac', margin: 0, lineHeight: 1.5 }}>
                  <strong>CSV export</strong> produces a real downloadable file with OWASP
                  formula-injection sanitization applied.
                  <br />
                  <strong>PDF export</strong> generates a genuine, structured binary PDF document with
                  executive summary, security score, and technical findings.
                </p>
              </div>
            )}

            {viewReport.status === 'failed' && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  padding: '14px 16px',
                  background: 'rgba(239,68,68,0.06)',
                  borderRadius: '10px',
                  border: '1px solid rgba(239,68,68,0.2)',
                }}
              >
                <AlertCircle size={15} color="#fca5a5" style={{ flexShrink: 0, marginTop: '1px' }} />
                <p style={{ fontSize: '0.8125rem', color: '#fca5a5', margin: 0 }}>
                  This report failed to generate. Retry or contact the platform administrator.
                </p>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default ReportsPage;
