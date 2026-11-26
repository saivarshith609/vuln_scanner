import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createDashboardSnapshotReport,
  exportDashboardPdf,
  generateDashboardPdf,
  getDashboardExportAvailability,
  getDashboardPdfFilename,
} from '../services/pdfExport';
import { getDashboard } from '../services/api';

const backendDashboard = {
  total_assets: 12,
  discovered_hosts: 9,
  active_scans: 2,
  total_scans: 27,
  completed_scans: 20,
  failed_scans: 3,
  cancelled_scans: 2,
  total_vulnerabilities: 7,
  resolved_vulnerabilities: 4,
  severity_counts: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
  recent_scans: [
    {
      id: 'scan-dashboard-1',
      target: 'production-edge.internal',
      scan_type: 'quick',
      status: 'completed',
      progress: 100,
      created_at: '2026-10-28T08:00:00Z',
      started_at: '2026-10-28T08:00:05Z',
      completed_at: '2026-10-28T08:01:05Z',
    },
  ],
  recent_vulnerabilities: [
    {
      id: 'vuln-dashboard-1',
      scan_id: 'scan-dashboard-1',
      asset_name: 'Production Edge Gateway',
      asset_target: 'production-edge.internal',
      title: 'Dashboard Snapshot TLS Finding',
      cve_id: 'CVE-2026-1310',
      severity: 'critical',
      cvss_score: 9.1,
      description: 'Backend-derived dashboard finding.',
      remediation: 'Apply the confirmed vendor update.',
      status: 'open',
      created_at: '2026-10-28T08:01:10Z',
    },
  ],
};

describe('Phase 13.1 dashboard PDF snapshot export', () => {
  const generatedAt = new Date('2026-10-28T12:34:56.000Z');
  const link = {
    href: '',
    download: '',
    click: vi.fn(),
  };

  beforeEach(() => {
    link.href = '';
    link.download = '';
    link.click.mockReset();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => backendDashboard,
    } as Response));
    vi.stubGlobal('window', {});
    vi.stubGlobal('document', {
      createElement: vi.fn().mockReturnValue(link),
      body: {
        appendChild: vi.fn(),
        removeChild: vi.fn(),
      },
    });
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:dashboard-pdf'),
      revokeObjectURL: vi.fn(),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('builds the snapshot only from mapped dashboard response data', async () => {
    const dashboard = await getDashboard();
    const report = createDashboardSnapshotReport(dashboard, generatedAt);

    expect(report.findingsSummary).toEqual({
      critical: 1,
      high: 2,
      medium: 3,
      low: 1,
      info: 0,
      total: 7,
    });
    expect(report.totalAssets).toBe(12);
    expect(report.totalScans).toBe(27);
    expect(report.securityScore).toBe(29);
    expect(report.snapshotData.metrics.discovered_hosts).toBe(9);
    expect(report.snapshotData.recent_findings[0].cve_id).toBe('CVE-2026-1310');
  });

  it('generates a genuine PDF with dashboard labels and meaningful backend content', async () => {
    const dashboard = await getDashboard();
    const doc = generateDashboardPdf(dashboard, generatedAt);
    const raw = doc.output();

    expect(raw.startsWith('%PDF-')).toBe(true);
    expect(raw).toContain('DASHBOARD SNAPSHOT SUMMARY');
    expect(raw).toContain('SCAN LIFECYCLE & ASSET TELEMETRY');
    expect(raw).toContain('production-edge.internal');
    expect(raw).toContain('Dashboard Snapshot TLS Finding');
    expect(raw).toContain('CVE-2026-1310');
  });

  it('uses the required dashboard filename and initiates one browser download', async () => {
    const dashboard = await getDashboard();
    const result = exportDashboardPdf(dashboard, generatedAt);
    const signature = new TextDecoder().decode((await result.blob.arrayBuffer()).slice(0, 5));

    expect(getDashboardPdfFilename(generatedAt)).toBe('vulnscanner-dashboard-2026-10-28.pdf');
    expect(result.filename).toBe('vulnscanner-dashboard-2026-10-28.pdf');
    expect(signature).toBe('%PDF-');
    expect(result.downloadInitiated).toBe(true);
    expect(link.click).toHaveBeenCalledOnce();
    expect(link.download).toBe(result.filename);
  });

  it('blocks missing, stale, refreshing, and duplicate export attempts', async () => {
    const dashboard = await getDashboard();

    expect(getDashboardExportAvailability(null, { isStale: false, isRefreshing: false, isExporting: false }).canExport).toBe(false);
    expect(getDashboardExportAvailability(dashboard, { isStale: true, isRefreshing: false, isExporting: false }).reason).toContain('stale');
    expect(getDashboardExportAvailability(dashboard, { isStale: false, isRefreshing: true, isExporting: false }).canExport).toBe(false);
    expect(getDashboardExportAvailability(dashboard, { isStale: false, isRefreshing: false, isExporting: true }).reason).toContain('already in progress');
    expect(getDashboardExportAvailability(dashboard, { isStale: false, isRefreshing: false, isExporting: false }).canExport).toBe(true);
  });

  it('propagates PDF download failures without reporting initiation', async () => {
    const dashboard = await getDashboard();
    vi.mocked(URL.createObjectURL).mockImplementation(() => {
      throw new Error('Browser object URL failed');
    });

    expect(() => exportDashboardPdf(dashboard, generatedAt)).toThrow('Browser object URL failed');
    expect(link.click).not.toHaveBeenCalled();
  });
});
