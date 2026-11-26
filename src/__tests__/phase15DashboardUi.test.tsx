// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardTelemetry } from '../types';

const testState = vi.hoisted(() => ({
  useAsync: vi.fn(),
  refetch: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock('../hooks/useAsync', () => ({ useAsync: testState.useAsync }));
vi.mock('../components/ui/Toast', () => ({ useToast: () => ({ showToast: testState.showToast }) }));
vi.mock('../store/ScanContext', () => ({
  useScans: () => ({ scans: [], isStale: false, error: null }),
}));
vi.mock('../components/dashboard/PostureScoreWidget', () => ({ PostureScoreWidget: () => null }));
vi.mock('../components/dashboard/VulnerabilityTrendChart', () => ({ VulnerabilityTrendChart: () => null }));
vi.mock('../components/dashboard/SeverityDonutChart', () => ({ SeverityDonutChart: () => null }));
vi.mock('../components/dashboard/CategoryBarChart', () => ({ CategoryBarChart: () => null }));
vi.mock('../components/dashboard/LiveScansWidget', () => ({ LiveScansWidget: () => null }));
vi.mock('../components/dashboard/RecentVulnerabilitiesTable', () => ({ RecentVulnerabilitiesTable: () => null }));

import { DashboardPage } from '../pages/DashboardPage';
import { DASHBOARD_REFRESH_INTERVAL_MS } from '../pages/DashboardPage';

const telemetry: DashboardTelemetry = {
  stats: {
    totalScans: 8,
    activeScans: 1,
    completedScans: 6,
    failedScans: 1,
    cancelledScans: 0,
    totalAssets: 12,
    discoveredHosts: 10,
    totalVulnerabilities: 3,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 1,
    lowCount: 0,
    infoCount: 0,
    resolvedCount: 2,
    averageRiskScore: 7.2,
    securityScore: 72,
  },
  trendData: [],
  severityDistribution: [],
  categoryData: [],
  recentScans: [],
  recentVulnerabilities: [],
};

function asyncState(overrides: Record<string, unknown> = {}) {
  return {
    data: null,
    state: 'loading',
    error: null,
    refetch: testState.refetch,
    isRefreshing: false,
    isStale: false,
    lastUpdated: null,
    ...overrides,
  };
}

describe('Phase 15 dashboard observable states', () => {
  beforeEach(() => {
    testState.refetch.mockReset();
    testState.showToast.mockReset();
    testState.useAsync.mockReset();
  });

  it('shows backend telemetry loading and prevents an unavailable export', () => {
    testState.useAsync.mockReturnValue(asyncState());
    render(<DashboardPage onNavigateToScans={vi.fn()} />);

    expect(screen.getByRole('status')).toHaveTextContent('Connecting to Security Telemetry API');
    expect(screen.getByRole('button', { name: 'Export PDF' })).toBeDisabled();
  });

  it('renders the API failure and exposes a working retry action', async () => {
    const user = userEvent.setup();
    testState.useAsync.mockReturnValue(asyncState({
      state: 'error',
      error: 'Dashboard service unavailable',
    }));
    render(<DashboardPage onNavigateToScans={vi.fn()} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Dashboard service unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry Request' }));
    expect(testState.refetch).toHaveBeenCalledOnce();
  });

  it('keeps backend-derived telemetry visible but marks a failed refresh stale', () => {
    testState.useAsync.mockReturnValue(asyncState({
      data: telemetry,
      state: 'success',
      error: 'Refresh failed',
      isStale: true,
      lastUpdated: Date.now(),
    }));
    render(<DashboardPage onNavigateToScans={vi.fn()} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Showing the last successful result. Refresh failed');
    expect(screen.getByText('Scan Engine')).toBeInTheDocument();
    expect(screen.getByText('8 total scans in database')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export PDF' })).toBeDisabled();
  });

  it('polls dashboard telemetry every 20 seconds, not at the scan-progress cadence', async () => {
    vi.useFakeTimers();
    testState.useAsync.mockReturnValue(asyncState({
      data: telemetry,
      state: 'success',
      lastUpdated: Date.now(),
    }));
    const { unmount } = render(<DashboardPage onNavigateToScans={vi.fn()} />);

    await vi.advanceTimersByTimeAsync(DASHBOARD_REFRESH_INTERVAL_MS - 1);
    expect(testState.refetch).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(testState.refetch).toHaveBeenCalledOnce();

    unmount();
    await vi.advanceTimersByTimeAsync(DASHBOARD_REFRESH_INTERVAL_MS);
    expect(testState.refetch).toHaveBeenCalledOnce();
  });

  it('does not overlap dashboard polling while a request is refreshing', async () => {
    vi.useFakeTimers();
    testState.useAsync.mockReturnValue(asyncState({
      data: telemetry,
      state: 'success',
      isRefreshing: true,
      lastUpdated: Date.now(),
    }));
    render(<DashboardPage onNavigateToScans={vi.fn()} />);

    await vi.advanceTimersByTimeAsync(DASHBOARD_REFRESH_INTERVAL_MS * 2);
    expect(testState.refetch).not.toHaveBeenCalled();
    expect(screen.getByRole('status')).toHaveTextContent('Refreshing data');
  });
});
