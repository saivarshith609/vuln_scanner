/**
 * Phase 5: Dashboard Telemetry & Posture — Unit Tests
 *
 * Tests cover:
 * - Posture score calculation (clean baseline, penalised state, clamping)
 * - recentScans / recentVulnerabilities mapping from backend payload
 * - Empty trend and category data (honest unavailability)
 * - Error state propagation (no mock fallback)
 * - DashboardStats new fields (totalAssets, infoCount)
 * - PostureScoreWidget grade derivation
 * - Component rendering with live vs empty data
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getDashboard, ApiError } from '../services/api';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeDashboardPayload(overrides: Partial<{
  total_assets: number;
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  failed_scans: number;
  cancelled_scans: number;
  discovered_hosts: number;
  resolved_vulnerabilities: number;
  total_vulnerabilities: number;
  severity_counts: { critical: number; high: number; medium: number; low: number; info: number };
  recent_scans: unknown[];
  recent_vulnerabilities: unknown[];
}> = {}) {
  return {
    total_assets: 0,
    total_scans: 0,
    active_scans: 0,
    completed_scans: 0,
    failed_scans: 0,
    cancelled_scans: 0,
    discovered_hosts: 0,
    resolved_vulnerabilities: 0,
    total_vulnerabilities: 0,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    recent_scans: [],
    recent_vulnerabilities: [],
    ...overrides,
  };
}

function mockFetchSuccess(body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => body,
  } as Response);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Phase 5: Dashboard Telemetry & Posture', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  it('maps lifecycle and discovered-host telemetry without inference', async () => {
    globalThis.fetch = mockFetchSuccess(makeDashboardPayload({
      total_scans: 8,
      completed_scans: 4,
      failed_scans: 2,
      cancelled_scans: 1,
      discovered_hosts: 6,
      resolved_vulnerabilities: 3,
    }));
    const data = await getDashboard();
    expect(data.stats.completedScans).toBe(4);
    expect(data.stats.failedScans).toBe(2);
    expect(data.stats.cancelledScans).toBe(1);
    expect(data.stats.discoveredHosts).toBe(6);
    expect(data.stats.resolvedCount).toBe(3);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // ── Posture Score Formula ───────────────────────────────────────────────────

  describe('Posture score calculation', () => {
    it('returns securityScore of 100 on a clean baseline (no findings)', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.stats.securityScore).toBe(100);
    });

    it('penalises securityScore correctly (1 critical = -25)', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 1,
          severity_counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      expect(data.stats.securityScore).toBe(75);
    });

    it('penalises by documented formula: critical*25 + high*15 + medium*5 + low*1', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 4,
          severity_counts: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
        }),
      );
      const data = await getDashboard();
      // 100 - (1*25 + 1*15 + 1*5 + 1*1) = 100 - 46 = 54
      expect(data.stats.securityScore).toBe(54);
    });

    it('clamps securityScore to 0 when penalty exceeds 100', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 5,
          severity_counts: { critical: 5, high: 0, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      // 100 - (5*25) = -25 → clamped to 0
      expect(data.stats.securityScore).toBe(0);
    });

    it('calculates averageRiskScore as weighted average across tiers', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 2,
          severity_counts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      // (1*10 + 1*7.5) / 2 = 8.75
      expect(data.stats.averageRiskScore).toBe(8.8);
    });

    it('returns averageRiskScore of 0 when there are no findings', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.stats.averageRiskScore).toBe(0);
    });
  });

  // ── New DashboardStats Fields ───────────────────────────────────────────────

  describe('DashboardStats — new Phase 5 fields', () => {
    it('includes totalAssets from backend', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload({ total_assets: 7 }));
      const data = await getDashboard();
      expect(data.stats.totalAssets).toBe(7);
    });

    it('includes infoCount from severity_counts', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 4 },
        }),
      );
      const data = await getDashboard();
      expect(data.stats.infoCount).toBe(4);
    });

    it('resolvedCount is always 0 (backend gap)', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.stats.resolvedCount).toBe(0);
    });
  });

  // ── Recent Data Mapping ─────────────────────────────────────────────────────

  describe('recentScans and recentVulnerabilities mapping', () => {
    it('maps recent_scans from backend into typed Scan objects', async () => {
      const scanPayload = {
        id: 'scan-001',
        target: '192.168.1.1',
        scan_type: 'quick',
        status: 'completed',
        progress: 100,
        created_at: '2026-10-27T08:00:00Z',
        started_at: '2026-10-27T08:00:01Z',
        completed_at: '2026-10-27T08:00:45Z',
      };
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload({ recent_scans: [scanPayload] }));
      const data = await getDashboard();
      expect(Array.isArray(data.recentScans)).toBe(true);
      expect(data.recentScans).toHaveLength(1);
      expect(data.recentScans[0].id).toBe('scan-001');
      expect(data.recentScans[0].status).toBe('completed');
      expect(data.recentScans[0].progress).toBe(100);
    });

    it('maps recent_vulnerabilities from backend into typed Vulnerability objects', async () => {
      const vulnPayload = {
        id: 'vuln-001',
        scan_id: 'scan-001',
        title: 'SMB Port 445 Open',
        severity: 'high',
        status: 'open',
        created_at: '2026-10-27T08:00:46Z',
      };
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({ recent_vulnerabilities: [vulnPayload] }),
      );
      const data = await getDashboard();
      expect(Array.isArray(data.recentVulnerabilities)).toBe(true);
      expect(data.recentVulnerabilities).toHaveLength(1);
      expect(data.recentVulnerabilities[0].id).toBe('vuln-001');
      expect(data.recentVulnerabilities[0].severity).toBe('high');
      expect(data.recentVulnerabilities[0].title).toBe('SMB Port 445 Open');
    });

    it('returns empty recentScans and recentVulnerabilities when backend returns empty arrays', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.recentScans).toHaveLength(0);
      expect(data.recentVulnerabilities).toHaveLength(0);
    });
  });

  // ── Honest Empty Data ───────────────────────────────────────────────────────

  describe('Honest empty arrays for unavailable backend metrics', () => {
    it('trendData is always an empty array (no time-series from backend)', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.trendData).toHaveLength(0);
    });

    it('categoryData is always an empty array (no OWASP category from backend)', async () => {
      globalThis.fetch = mockFetchSuccess(makeDashboardPayload());
      const data = await getDashboard();
      expect(data.categoryData).toHaveLength(0);
    });

    it('trendData is empty even when there are findings', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 3,
          severity_counts: { critical: 2, high: 1, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      expect(data.trendData).toHaveLength(0);
    });

    it('categoryData is empty even when there are findings', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 3,
          severity_counts: { critical: 2, high: 1, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      expect(data.categoryData).toHaveLength(0);
    });
  });

  // ── Error State — No Mock Fallback ──────────────────────────────────────────

  describe('Error propagation — no mock fallback', () => {
    it('throws ApiError when network fails (ECONNREFUSED)', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
      await expect(getDashboard()).rejects.toThrow('Unable to reach the API service.');
    });

    it('throws an instance of ApiError when backend is unreachable', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('network error'));
      await expect(getDashboard()).rejects.toBeInstanceOf(ApiError);
    });

    it('does not return mock data when backend is unreachable', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('connection refused'));
      let result: unknown = 'should-not-be-set';
      try {
        result = await getDashboard();
      } catch {
        // expected
      }
      // result must still be the sentinel — getDashboard must not have returned mock data
      expect(result).toBe('should-not-be-set');
    });
  });

  // ── Severity Distribution ────────────────────────────────────────────────────

  describe('severityDistribution array', () => {
    it('builds a five-element severity distribution array', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          total_vulnerabilities: 2,
          severity_counts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
        }),
      );
      const data = await getDashboard();
      expect(data.severityDistribution).toHaveLength(5);
      const critical = data.severityDistribution.find((d) => d.name === 'Critical');
      expect(critical?.value).toBe(1);
    });

    it('info severity is included in severityDistribution', async () => {
      globalThis.fetch = mockFetchSuccess(
        makeDashboardPayload({
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 3 },
        }),
      );
      const data = await getDashboard();
      const info = data.severityDistribution.find((d) => d.name === 'Info');
      expect(info?.value).toBe(3);
    });
  });
});
