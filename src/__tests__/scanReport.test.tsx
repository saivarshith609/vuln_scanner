// @vitest-environment jsdom

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../components/ui/Toast';
import { ScanReportPage } from '../pages/ScanReportPage';
import { getScanReport } from '../services/api';
import { downloadScanReportPdf } from '../services/scanReportPdf';
import type { ScanReportDetail } from '../types';

vi.mock('../services/api', () => ({ getScanReport: vi.fn() }));
vi.mock('../services/scanReportPdf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/scanReportPdf')>();
  return { ...actual, downloadScanReportPdf: vi.fn(() => 'VulnScanner_192.0.2.24_2026-10-28.pdf') };
});

const report: ScanReportDetail = {
  scan_id: '5d44ac60-d5e4-4e19-b76e-178211b32fea',
  target: '192.0.2.24',
  status: 'completed',
  progress: 100,
  scan_profile: 'quick',
  scanner: 'Nmap',
  created_at: '2026-10-28T08:00:00Z',
  started_at: '2026-10-28T08:00:02Z',
  completed_at: '2026-10-28T08:01:16Z',
  duration_seconds: 74,
  resolved_addresses: ['192.0.2.24'],
  authorization_mode: null,
  recorded_configuration: null,
  port_inventory_recorded: true,
  summary: {
    total_ports_examined: null,
    recorded_port_entries: 2,
    open_ports: 1,
    closed_or_filtered_ports: 1,
    identified_services: 1,
    findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 },
  },
  ports: [
    { id: 'port-1', host_address: '192.0.2.24', host_state: 'up', port: 22, protocol: 'tcp', state: 'open', service_name: 'ssh', product: 'OpenSSH', version: '9.6', extra_information: 'protocol 2.0' },
    { id: 'port-2', host_address: '192.0.2.24', host_state: 'up', port: 443, protocol: 'tcp', state: 'filtered' },
  ],
  findings: [{
    id: 'finding-1', title: 'Recorded SSH weakness', severity: 'high', cve_id: 'CVE-2026-0001', cvss_score: 8.1,
    cvss_vector: 'CVSS:3.1/AV:N', affected_target: '192.0.2.24', port: 22, service_name: 'ssh',
    description: 'Fixture description', evidence: 'Fixture evidence', remediation: 'Upgrade OpenSSH', status: 'confirmed',
  }],
  limitations: ['Exact port configuration was not retained.'],
};

const renderPage = () => render(
  <ToastProvider><ScanReportPage scanId={report.scan_id} onBack={vi.fn()} /></ToastProvider>,
);

describe('scan report viewer', () => {
  beforeEach(() => {
    vi.mocked(getScanReport).mockResolvedValue(report);
    vi.mocked(downloadScanReportPdf).mockClear();
  });

  it('opens the selected scan data without automatically downloading', async () => {
    renderPage();
    expect(await screen.findByRole('heading', { name: 'Vulnerability Assessment Report' })).toBeInTheDocument();
    expect(getScanReport).toHaveBeenCalledWith(report.scan_id, expect.any(AbortSignal));
    expect(screen.getAllByText('192.0.2.24').length).toBeGreaterThan(0);
    expect(screen.getByText('22')).toBeInTheDocument();
    expect(screen.getAllByText('TCP')).toHaveLength(2);
    expect(screen.getByText('OpenSSH')).toBeInTheDocument();
    expect(screen.getByText('9.6')).toBeInTheDocument();
    expect(screen.getByText('Recorded SSH weakness')).toBeInTheDocument();
    expect(downloadScanReportPdf).not.toHaveBeenCalled();
  });

  it('downloads once per click with the exact report payload and no confirmation', async () => {
    renderPage();
    const button = await screen.findByRole('button', { name: 'Download PDF' });
    fireEvent.click(button);
    expect(downloadScanReportPdf).toHaveBeenCalledTimes(1);
    expect(downloadScanReportPdf).toHaveBeenCalledWith(report);
    expect(screen.getByText(/PDF download started/)).toBeInTheDocument();
  });

  it('filters actual vulnerability records by severity and search', async () => {
    renderPage();
    await screen.findByText('Recorded SSH weakness');
    fireEvent.change(screen.getByLabelText('Filter findings by severity'), { target: { value: 'low' } });
    expect(screen.getByText('No findings match the current filters.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Filter findings by severity'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'CVE-2026-0001' } });
    expect(screen.getByText('Recorded SSH weakness')).toBeInTheDocument();
  });

  it.each([
    ['running', 'Scan in progress'],
    ['failed', 'Scan failed before'],
    ['cancelled', 'Scan cancelled'],
    ['completed', 'no persisted port inventory'],
  ] as const)('distinguishes the %s empty inventory state', async (status, message) => {
    vi.mocked(getScanReport).mockResolvedValue({ ...report, status, ports: [], port_inventory_recorded: false });
    renderPage();
    expect(await screen.findByText(new RegExp(message, 'i'))).toBeInTheDocument();
  });

  it('shows a retryable API error', async () => {
    vi.mocked(getScanReport).mockRejectedValueOnce(new Error('Report access denied')).mockResolvedValueOnce(report);
    renderPage();
    expect(await screen.findByText('Report access denied')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry request/i }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Vulnerability Assessment Report' })).toBeInTheDocument());
  });
});
