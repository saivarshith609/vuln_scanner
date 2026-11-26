import { describe, it, expect, vi } from 'vitest';
import {
  getDashboard,
  getScans,
  getScan,
  createScan,
  cancelScan,
  getScanResults,
  getAssets,
  getAsset,
  createAsset,
  updateAsset,
  deleteAsset,
  getVulnerabilities,
  getVulnerability,
  updateVulnerabilityStatus,
  getReports,
  getReport,
  generateReport,
  getStats,
} from '../services/api';

describe('Phase 3: REST API Service Layer Integration', () => {
  it('fetches dashboard metrics, telemetry, and posture score via mocked fetch', async () => {
    const originalFetch = globalThis.fetch;
    const mockDashboardPayload = {
      total_assets: 3,
      total_scans: 5,
      active_scans: 1,
      total_vulnerabilities: 4,
      severity_counts: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
      recent_scans: [
        {
          id: 'scan-abc',
          target: '127.0.0.1',
          scan_type: 'quick',
          status: 'completed',
          progress: 100,
          created_at: '2026-10-27T12:00:00Z',
          started_at: '2026-10-27T12:00:01Z',
          completed_at: '2026-10-27T12:00:30Z',
        },
      ],
      recent_vulnerabilities: [
        {
          id: 'vuln-xyz',
          scan_id: 'scan-abc',
          title: 'Open Port 445 — SMB Accessible',
          severity: 'high',
          status: 'open',
          created_at: '2026-10-27T12:00:30Z',
        },
      ],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockDashboardPayload,
    } as Response);

    try {
      const data = await getDashboard();
      expect(data).toBeDefined();
      expect(data.stats).toBeDefined();
      // Phase 5: new fields
      expect(data.stats.totalAssets).toBe(3);
      expect(data.stats.infoCount).toBe(0);
      expect(data.stats.totalVulnerabilities).toBe(4);
      expect(data.stats.criticalCount).toBe(1);
      // Posture formula: 100 - (1*25 + 1*15 + 1*5 + 1*1) = 54
      expect(data.stats.securityScore).toBe(54);
      expect(data.stats.securityScore).toBeGreaterThanOrEqual(0);
      expect(data.stats.securityScore).toBeLessThanOrEqual(100);
      // Phase 5: empty arrays for metrics the backend does not provide
      expect(Array.isArray(data.trendData)).toBe(true);
      expect(data.trendData).toHaveLength(0);
      expect(Array.isArray(data.categoryData)).toBe(true);
      expect(data.categoryData).toHaveLength(0);
      // Phase 5: recent data mapped from backend payload
      expect(Array.isArray(data.severityDistribution)).toBe(true);
      expect(Array.isArray(data.recentScans)).toBe(true);
      expect(data.recentScans).toHaveLength(1);
      expect(data.recentScans[0].id).toBe('scan-abc');
      expect(Array.isArray(data.recentVulnerabilities)).toBe(true);
      expect(data.recentVulnerabilities).toHaveLength(1);
      expect(data.recentVulnerabilities[0].id).toBe('vuln-xyz');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('throws ApiError when dashboard backend is unreachable (no mock fallback)', async () => {
    const originalFetch = globalThis.fetch;
    // Simulate network failure (null returned by request() helper)
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    try {
      await expect(getDashboard()).rejects.toThrow('Unable to reach the API service.');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('fetches and creates scans', async () => {
    const originalFetch = globalThis.fetch;
    const mockScanResponse = {
      id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
      target: '127.0.0.1',
      scan_type: 'full',
      status: 'queued',
      progress: 0,
      created_at: '2026-10-27T12:00:00Z',
    };

    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/cancel') && init?.method === 'POST') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ ...mockScanResponse, status: 'cancelled' }),
        } as Response;
      }
      if (urlStr.includes('/scans') && init?.method === 'POST') {
        return {
          ok: true,
          status: 201,
          json: async () => mockScanResponse,
        } as Response;
      }
      if (urlStr.includes('/scans/34dffa0e-d82d-40c4-898d-39d634e6426d')) {
        return {
          ok: true,
          status: 200,
          json: async () => mockScanResponse,
        } as Response;
      }
      if (urlStr.includes('/scan-results')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ items: [], total: 0, page: 1, size: 200, pages: 0 }),
        } as Response;
      }
      if (urlStr.includes('/scans')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ items: [mockScanResponse], total: 1, page: 1, size: 100, pages: 1 }),
        } as Response;
      }
      return originalFetch(url, init);
    });

    try {
      const scans = await getScans();
      expect(Array.isArray(scans)).toBe(true);

      const newScan = await createScan({
        name: 'CI/CD Automated Integration Audit',
        targetUrl: 'https://staging.enterprise.internal',
        type: 'full',
      });
      expect(newScan.id).toBeDefined();
      expect(newScan.name).toContain('CI/CD Automated Integration Audit');
      expect(['queued', 'running']).toContain(newScan.status);
      expect(newScan.progress).toBe(0);

      const fetchedScan = await getScan(newScan.id);
      if (fetchedScan) {
        expect(fetchedScan.id).toBe(newScan.id);
      }

      const results = await getScanResults(newScan.id);
      expect(Array.isArray(results)).toBe(true);

      const cancelled = await cancelScan(newScan.id);
      if (cancelled) {
        expect(cancelled.id).toBe(newScan.id);
        expect(cancelled.status).toBe('cancelled');
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('manages asset lifecycle: get, create, update, delete', async () => {
    const originalFetch = globalThis.fetch;
    const backendAsset = {
      id: 'asset-api-test', name: 'k8s-worker-node-test', asset_type: 'server', target: '10.244.1.88',
      created_at: '2026-10-27T12:00:00Z', updated_at: '2026-10-27T12:00:00Z',
    };
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'DELETE') return { ok: true, status: 204 } as Response;
      if (init?.method === 'PATCH') return { ok: true, status: 200, json: async () => ({ ...backendAsset, name: 'k8s-worker-node-prod' }) } as Response;
      if (init?.method === 'POST') return { ok: true, status: 201, json: async () => backendAsset } as Response;
      return { ok: true, status: 200, json: async () => (url.endsWith('/asset-api-test') ? backendAsset : { items: [backendAsset], total: 1, page: 1, size: 100, pages: 1 }) } as Response;
    });
    try {
      const assets = await getAssets();
      expect(assets).toHaveLength(1);
      const newAsset = await createAsset({ name: 'k8s-worker-node-test', ip: '10.244.1.88', type: 'server' });
      expect(newAsset.name).toBe('k8s-worker-node-test');
      const singleAsset = await getAsset(newAsset.id);
      expect(singleAsset?.id).toBe(newAsset.id);
      const updated = await updateAsset(newAsset.id, { name: 'k8s-worker-node-prod', status: 'online' });
      expect(updated?.name).toBe('k8s-worker-node-prod');
      expect((await deleteAsset(newAsset.id)).success).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('queries vulnerabilities and updates triage status', async () => {
    const originalFetch = globalThis.fetch;
    const backendVulnerability = { id: 'vuln-api-test', scan_id: 'scan-api-test', title: 'Confirmed finding', severity: 'high', status: 'open', created_at: '2026-10-27T12:00:00Z' };
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'PATCH') return { ok: true, status: 200, json: async () => ({ ...backendVulnerability, status: 'resolved' }) } as Response;
      return { ok: true, status: 200, json: async () => (url.includes('/vulnerabilities/vuln-api-test') ? backendVulnerability : { items: [backendVulnerability], total: 1, page: 1, size: 100, pages: 1 }) } as Response;
    });
    try {
      const vulns = await getVulnerabilities();
      expect(vulns).toHaveLength(1);
      const fetched = await getVulnerability(vulns[0].id);
      expect(fetched?.id).toBe(vulns[0].id);
      const updated = await updateVulnerabilityStatus(vulns[0].id, 'resolved');
      expect(updated.success).toBe(true);
      expect(updated.vulnerability?.status).toBe('resolved');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('manages report generation and queries', async () => {
    const originalFetch = globalThis.fetch;
    const mockBackendReport = {
      id: 'rpt-test-uuid',
      report_code: 'RPT-20261027-TEST',
      name: 'Quarterly Board Security Review',
      target: 'Production Cloud Perimeter',
      report_type: 'executive',
      format: 'pdf',
      status: 'completed',
      scan_date: '2026-10-27',
      date_from: null,
      date_to: null,
      file_size: '1.2 MB',
      findings_summary: { critical: 1, high: 2, medium: 3, low: 4, info: 5, total: 15 },
      security_score: 72,
      total_assets: 10,
      total_scans: 5,
      created_at: '2026-10-27T12:00:00Z',
      updated_at: '2026-10-27T12:00:00Z',
      download_url: null,
      snapshot_data: { total_assets: 10, total_scans: 5 },
    };

    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.includes('/reports') && init?.method === 'POST') {
        return {
          ok: true,
          status: 201,
          json: async () => mockBackendReport,
        } as Response;
      }
      if (urlStr.includes('/reports/rpt-test-uuid')) {
        return {
          ok: true,
          status: 200,
          json: async () => mockBackendReport,
        } as Response;
      }
      if (urlStr.includes('/reports')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [mockBackendReport],
            total: 1,
            page: 1,
            size: 100,
            pages: 1,
          }),
        } as Response;
      }
      return originalFetch(url, init);
    });

    try {
      const reports = await getReports();
      expect(Array.isArray(reports)).toBe(true);
      expect(reports.length).toBeGreaterThan(0);

      const targetReport = reports[0];
      const single = await getReport(targetReport.id);
      expect(single).toBeDefined();
      expect(single?.id).toBe(targetReport.id);

      const generated = await generateReport({
        name: 'Quarterly Board Security Review',
        target: 'Production Cloud Perimeter',
        type: 'executive',
        format: 'pdf',
      });
      expect(generated.id).toBeDefined();
      expect(generated.name).toBe('Quarterly Board Security Review');
      expect(generated.status).toBe('ready'); // 'completed' maps to 'ready'
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('fetches statistics', async () => {
    // getStats() delegates to getDashboard() — mock fetch so the test is deterministic
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        total_assets: 2,
        total_scans: 10,
        active_scans: 0,
        total_vulnerabilities: 3,
        severity_counts: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
        recent_scans: [],
        recent_vulnerabilities: [],
      }),
    } as Response);
    try {
      const stats = await getStats();
      expect(stats.totalScans).toBeGreaterThanOrEqual(0);
      expect(stats.totalVulnerabilities).toBeGreaterThanOrEqual(0);
      expect(stats.securityScore).toBeGreaterThanOrEqual(0);
      // Phase 5: new fields
      expect(stats.totalAssets).toBeGreaterThanOrEqual(0);
      expect(stats.infoCount).toBeGreaterThanOrEqual(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
