import React, { useEffect, useMemo, useRef, useState } from 'react';
import { StatCard } from '../components/ui/StatCard';
import { Button } from '../components/ui/Button';
import { PostureScoreWidget } from '../components/dashboard/PostureScoreWidget';
import { VulnerabilityTrendChart } from '../components/dashboard/VulnerabilityTrendChart';
import { SeverityDonutChart } from '../components/dashboard/SeverityDonutChart';
import { CategoryBarChart } from '../components/dashboard/CategoryBarChart';
import { LiveScansWidget } from '../components/dashboard/LiveScansWidget';
import { RecentVulnerabilitiesTable } from '../components/dashboard/RecentVulnerabilitiesTable';
import { DashboardSkeleton } from '../components/dashboard/DashboardSkeleton';
import { StateView } from '../components/ui/StateView';
import { useAsync } from '../hooks/useAsync';
import { useToast } from '../components/ui/Toast';
import { getDashboard } from '../services/api';
import { getDashboardExportAvailability } from '../services/pdfExport';
import { useScans } from '../store/ScanContext';
import { getActiveScanCount } from '../utils/scanActivity';
import {
  Flame,
  AlertTriangle,
  ScanSearch,
  CheckCircle2,
  Download,
  Play,
  RotateCw,
} from 'lucide-react';
import './DashboardPage.css';

export const DASHBOARD_REFRESH_INTERVAL_MS = 20_000;
export const KPI_LOADING_SEQUENCE_MS = 2_100;

export interface DashboardPageProps {
  onNavigateToScans: () => void;
  onOpenNewScan?: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onNavigateToScans,
  onOpenNewScan,
}) => {
  const { showToast } = useToast();
  const {
    scans,
    isStale: isScanStateStale,
    error: scanStateError,
  } = useScans();
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [isExporting, setIsExporting] = useState(false);
  const [isKpiSequenceActive, setIsKpiSequenceActive] = useState(true);
  const [isManualRefreshCycle, setIsManualRefreshCycle] = useState(false);
  const exportInProgressRef = useRef(false);
  const kpiSequenceTimerRef = useRef<number | null>(null);

  // Single source of truth: the /dashboard endpoint supplies all dashboard telemetry.
  // recentScans and recentVulnerabilities come from the same payload — no extra calls.
  const { data: dashboardData, state: dashState, error: dashError, refetch: refetchDash, isRefreshing, isStale, lastUpdated } = useAsync(getDashboard);
  const dashboardRefreshingRef = useRef(isRefreshing);

  useEffect(() => {
    dashboardRefreshingRef.current = isRefreshing;
  }, [isRefreshing]);

  useEffect(() => {
    const pollDashboard = () => {
      if (document.visibilityState === 'visible' && !dashboardRefreshingRef.current) {
        refetchDash();
      }
    };
    const interval = window.setInterval(pollDashboard, DASHBOARD_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(interval);
  }, [refetchDash]);

  const startKpiLoadingSequence = () => {
    if (kpiSequenceTimerRef.current !== null) {
      window.clearTimeout(kpiSequenceTimerRef.current);
    }

    setIsKpiSequenceActive(true);
    kpiSequenceTimerRef.current = window.setTimeout(() => {
      setIsKpiSequenceActive(false);
      kpiSequenceTimerRef.current = null;
    }, KPI_LOADING_SEQUENCE_MS);
  };

  useEffect(() => {
    startKpiLoadingSequence();
    return () => {
      if (kpiSequenceTimerRef.current !== null) {
        window.clearTimeout(kpiSequenceTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (isManualRefreshCycle && !isRefreshing && !isKpiSequenceActive) {
      setIsManualRefreshCycle(false);
    }
  }, [isKpiSequenceActive, isManualRefreshCycle, isRefreshing]);

  const handleRefresh = () => {
    setIsManualRefreshCycle(true);
    startKpiLoadingSequence();
    refetchDash();
    showToast('info', 'Refreshing security telemetry...');
  };

  const exportAvailability = getDashboardExportAvailability(dashboardData, {
    isStale,
    isRefreshing,
    isExporting,
  });

  const handleExport = async () => {
    if (exportInProgressRef.current) return;
    if (!exportAvailability.canExport || !dashboardData) {
      showToast('warning', exportAvailability.reason || 'Dashboard telemetry is unavailable.');
      return;
    }

    exportInProgressRef.current = true;
    setIsExporting(true);
    try {
      // Yield once so the pending state is painted before jsPDF performs synchronous work.
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
      const { exportDashboardPdf } = await import('../services/pdfExport');
      const result = exportDashboardPdf(dashboardData);
      if (!result.downloadInitiated) {
        throw new Error('The browser did not initiate the dashboard PDF download.');
      }
      showToast('success', `Dashboard snapshot downloaded as ${result.filename}.`);
    } catch (err: unknown) {
      showToast('error', err instanceof Error ? err.message : 'Dashboard PDF generation failed.');
    } finally {
      exportInProgressRef.current = false;
      setIsExporting(false);
    }
  };

  const stats = dashboardData?.stats;
  const trendData = dashboardData?.trendData ?? [];
  const severityDistribution = dashboardData?.severityDistribution ?? [];
  const categoryData = dashboardData?.categoryData ?? [];
  // Consume recent data directly from the dashboard response — no separate API calls.
  const recentVulnerabilities = dashboardData?.recentVulnerabilities ?? [];
  // ScanContext is the single live representation shared with scan management.
  const recentScans = [...scans].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  const activeScanCount = useMemo(() => getActiveScanCount(scans), [scans]);
  const showKpiLoading = isKpiSequenceActive || isManualRefreshCycle;
  return (
    <div className="vs-dashboard-container animate-fade-in">
      {/* Top Banner / Actions Bar */}
      <div className="vs-dashboard-header">
        <div>
          <h2 className="vs-dashboard-header__title">Executive Security Telemetry</h2>
          <p className="vs-dashboard-header__subtitle">
            Live threat posture, scanner engine telemetry, and confirmed finding data from the PostgreSQL database
          </p>
        </div>

        <div className="vs-dashboard-header__actions">
          {/* Time range selector */}
          <div className="vs-time-selector">
            {(['7d', '30d', '90d'] as const).map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => setTimeRange(r)}
                aria-pressed={timeRange === r}
                className={`vs-time-btn ${timeRange === r ? 'vs-time-btn--active' : ''}`}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            leftIcon={<RotateCw size={14} className={isRefreshing ? 'animate-spin' : ''} />}
            isLoading={isRefreshing}
            onClick={handleRefresh}
          >
            Refresh
          </Button>

          <Button
            variant="secondary"
            size="sm"
            leftIcon={<Download size={14} />}
            isLoading={isExporting}
            disabled={!exportAvailability.canExport}
            onClick={handleExport}
            title={exportAvailability.reason || 'Download a PDF snapshot of the latest dashboard telemetry'}
          >
            Export PDF
          </Button>

          {onOpenNewScan && (
            <Button
              variant="primary"
              size="sm"
              leftIcon={<Play size={14} />}
              onClick={onOpenNewScan}
            >
              Run Scan
            </Button>
          )}
        </div>
      </div>

      {(dashState === 'loading' || dashState === 'idle') ? (
        <DashboardSkeleton />
      ) : <StateView
        state={dashState}
        error={dashError}
        onRetry={refetchDash}
        isRefreshing={isRefreshing}
        isStale={isStale}
        staleError={dashError}
        lastUpdated={lastUpdated}
        loadingMessage="Connecting to Security Telemetry API..."
      >
        {stats && (
          <>
            {/* Row 1: KPI Stat Cards — all values are live from the backend */}
            <div className="vs-dashboard-kpi-grid">
              <StatCard
                label="Critical Exploits"
                value={stats.criticalCount}
                subtitle={stats.criticalCount === 0 ? 'No critical findings' : `${stats.criticalCount} confirmed critical finding${stats.criticalCount !== 1 ? 's' : ''}`}
                icon={<Flame size={20} />}
                accent="critical"
                isLoading={showKpiLoading}
                loadingIndex={0}
              />
              <StatCard
                label="High Severity Flaws"
                value={stats.highCount}
                subtitle={stats.highCount === 0 ? 'No high severity findings' : `${stats.highCount} high severity finding${stats.highCount !== 1 ? 's' : ''}`}
                icon={<AlertTriangle size={20} />}
                accent="high"
                isLoading={showKpiLoading}
                loadingIndex={1}
              />
              <StatCard
                label="Total Findings"
                value={stats.totalVulnerabilities}
                subtitle={stats.totalVulnerabilities === 0 ? 'Clean baseline — no vulnerabilities' : `${stats.resolvedCount} resolved (backend gap)`}
                icon={<CheckCircle2 size={20} />}
                accent="low"
                isLoading={showKpiLoading}
                loadingIndex={2}
              />
              <StatCard
                label="Scan Engine"
                value={`${stats.activeScans} Active`}
                subtitle={`${stats.totalScans} total scan${stats.totalScans !== 1 ? 's' : ''} in database`}
                icon={<ScanSearch size={20} />}
                accent="brand"
                onClick={onNavigateToScans}
                isLoading={showKpiLoading}
                loadingIndex={3}
              />
            </div>

            {/* Row 2: Posture Score + Vulnerability Trend */}
            <div className="vs-dashboard-grid-hero">
              <PostureScoreWidget
                score={stats.securityScore}
                totalVulnerabilities={stats.totalVulnerabilities}
                criticalCount={stats.criticalCount}
                highCount={stats.highCount}
                totalAssets={stats.totalAssets}
                activeScans={stats.activeScans}
              />
              <VulnerabilityTrendChart data={trendData} />
            </div>

            {/* Row 3: Severity Breakdown + OWASP Categories + Live Scans */}
            <div className="vs-dashboard-grid-triplet">
              <SeverityDonutChart data={severityDistribution} total={stats.totalVulnerabilities} />
              <CategoryBarChart data={categoryData} />
              <LiveScansWidget
                scans={recentScans.slice(0, 3)}
                activeScanCount={activeScanCount}
                activityIsStale={isScanStateStale || Boolean(scanStateError)}
                onViewAllScans={onNavigateToScans}
              />
            </div>

            {/* Row 4: Findings & CVE Triage Table */}
            <div className="vs-dashboard-row-full">
              <RecentVulnerabilitiesTable vulnerabilities={recentVulnerabilities} />
            </div>
          </>
        )}
      </StateView>}
    </div>
  );
};

export default DashboardPage;
