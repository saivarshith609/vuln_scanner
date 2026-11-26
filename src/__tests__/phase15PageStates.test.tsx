// @vitest-environment jsdom

import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const pageMocks = vi.hoisted(() => ({
  useAsync: vi.fn(),
  useScans: vi.fn(),
  getAuthorizedTargets: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock('../hooks/useAsync', () => ({ useAsync: pageMocks.useAsync }));
vi.mock('../store/ScanContext', () => ({ useScans: pageMocks.useScans }));
vi.mock('../components/ui/Toast', () => ({ useToast: () => ({ showToast: pageMocks.showToast }) }));
vi.mock('../services/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/api')>();
  return { ...actual, getAuthorizedTargets: pageMocks.getAuthorizedTargets };
});

import { AssetsPage } from '../pages/AssetsPage';
import { ReportsPage } from '../pages/ReportsPage';
import { ScansPage } from '../pages/ScansPage';
import { SettingsPage } from '../pages/SettingsPage';
import { VulnerabilitiesPage } from '../pages/VulnerabilitiesPage';
import { AuthorizedTargetsManager } from '../components/targets/AuthorizedTargetsManager';

function hookState(overrides: Record<string, unknown> = {}) {
  return {
    data: null,
    state: 'loading',
    error: null,
    refetch: vi.fn(),
    isRefreshing: false,
    isStale: false,
    lastUpdated: null,
    ...overrides,
  };
}

function scanState(overrides: Record<string, unknown> = {}) {
  return {
    scans: [],
    isLoading: true,
    isRefreshing: false,
    isStale: false,
    lastUpdated: null,
    error: null,
    addScan: vi.fn(),
    stopScan: vi.fn(),
    rerunScan: vi.fn(),
    deleteScan: vi.fn(),
    refreshScans: vi.fn(),
    ...overrides,
  };
}

describe('Phase 15 page state regressions', () => {
  beforeEach(() => {
    pageMocks.useAsync.mockReset().mockReturnValue(hookState());
    pageMocks.useScans.mockReset().mockReturnValue(scanState());
    pageMocks.getAuthorizedTargets.mockReset();
    pageMocks.showToast.mockReset();
  });

  it.each([
    ['assets', () => <AssetsPage />, 'Loading assets...'],
    ['vulnerabilities', () => <VulnerabilitiesPage />, 'Fetching vulnerabilities...'],
    ['reports', () => <ReportsPage />, 'Loading report archive...'],
    ['settings', () => <SettingsPage />, 'Loading platform settings'],
    ['scans', () => <ScansPage onOpenNewScanModal={vi.fn()} />, 'Fetching scan pipelines and telemetry...'],
  ])('renders the %s loading state accessibly', (_name, createPage, message) => {
    render(createPage());
    expect(screen.getByText(message, { exact: false })).toBeInTheDocument();
  });

  it.each([
    ['assets', () => <AssetsPage />, 'No assets registered yet'],
    ['vulnerabilities', () => <VulnerabilitiesPage />, 'No vulnerabilities recorded'],
    ['reports', () => <ReportsPage />, 'No security reports in archive'],
  ])('renders an honest empty state for %s', (_name, createPage, message) => {
    pageMocks.useAsync.mockReturnValue(hookState({ data: [], state: 'success' }));
    render(createPage());
    expect(screen.getByText(message)).toBeInTheDocument();
  });

  it('renders the scan empty state without fabricated active jobs', () => {
    pageMocks.useScans.mockReturnValue(scanState({ isLoading: false }));
    render(<ScansPage onOpenNewScanModal={vi.fn()} />);
    expect(screen.getByText('No security scans executed yet')).toBeInTheDocument();
    expect(screen.queryByText(/active scan/i)).not.toBeInTheDocument();
  });

  it('exposes a working retry action after a page request fails', async () => {
    const user = userEvent.setup();
    const refetch = vi.fn();
    pageMocks.useAsync.mockReturnValue(hookState({
      state: 'error',
      error: 'Asset service unavailable',
      refetch,
    }));
    render(<AssetsPage />);

    expect(screen.getByRole('alert')).toHaveTextContent('Asset service unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry Request' }));
    expect(refetch).toHaveBeenCalledOnce();
  });

  it('moves authorized targets from loading to a truthful empty state', async () => {
    let resolveTargets!: (value: { items: never[] }) => void;
    pageMocks.getAuthorizedTargets.mockReturnValueOnce(new Promise((resolve) => {
      resolveTargets = resolve;
    }));
    render(<AuthorizedTargetsManager />);
    expect(screen.getByText('Loading authorized scan targets...')).toBeInTheDocument();

    await act(async () => resolveTargets({ items: [] }));
    expect(await screen.findByText('No Authorized Scan Targets Configured')).toBeInTheDocument();
  });

  it('allows an authorized-target fetch failure to be retried without a real request', async () => {
    const user = userEvent.setup();
    pageMocks.getAuthorizedTargets
      .mockRejectedValueOnce(new Error('Allow-list service unavailable'))
      .mockResolvedValueOnce({ items: [] });
    render(<AuthorizedTargetsManager />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Allow-list service unavailable');
    await user.click(screen.getByRole('button', { name: 'Retry Request' }));

    await waitFor(() => expect(pageMocks.getAuthorizedTargets).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('No Authorized Scan Targets Configured')).toBeInTheDocument();
  });
});
