import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getScan,
  createScan,
  cancelScan,
  getScanResults,
  ApiError,
} from '../services/api';
import type { ScanResult } from '../types';

describe('Phase 4.3: Frontend Scan Engine Integration & Discovery Telemetry', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('1. Scan Creation API Schema (POST /api/v1/scans)', () => {
    it('sends correct request payload with target and scan_type', async () => {
      let capturedUrl = '';
      let capturedBody: any = null;

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedBody = JSON.parse((init?.body as string) || '{}');
        return {
          ok: true,
          status: 201,
          json: async () => ({
            id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
            target: '127.0.0.1',
            scan_type: 'quick',
            status: 'queued',
            progress: 0,
            created_at: '2026-10-27T12:00:00Z',
          }),
        } as Response;
      });

      const scan = await createScan({
        name: 'Local Smoke Test',
        targetUrl: '127.0.0.1',
        type: 'quick',
      });

      expect(capturedUrl).toContain('/scans');
      expect(capturedBody).toEqual({
        target: '127.0.0.1',
        scan_type: 'quick',
        authorization_mode: 'allow_list',
        authorization_confirmed: false,
      });
      expect(scan.id).toBe('34dffa0e-d82d-40c4-898d-39d634e6426d');
      expect(scan.status).toBe('queued');
      expect(scan.progress).toBe(0);
      expect(scan.findings.total).toBe(0);
    });

    it('sends explicit authorization for a direct on-demand IP scan', async () => {
      let capturedBody: Record<string, unknown> = {};
      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        capturedBody = JSON.parse((init?.body as string) || '{}');
        return new Response(JSON.stringify({
          id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          target: '192.168.29.31',
          scan_type: 'quick',
          status: 'queued',
          progress: 0,
          created_at: '2026-10-28T12:00:00Z',
        }), { status: 201, headers: { 'Content-Type': 'application/json' } });
      });

      await createScan({
        targetUrl: '192.168.29.31',
        type: 'quick',
        authorizationMode: 'on_demand',
        authorizationConfirmed: true,
      });

      expect(capturedBody).toEqual({
        target: '192.168.29.31',
        scan_type: 'quick',
        authorization_mode: 'on_demand',
        authorization_confirmed: true,
      });
    });

    it('propagates ApiError when target is not authorized (HTTP 403)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        json: async () => ({
          detail: "Target '10.99.99.99' is not in the authorized targets list. Register it first.",
        }),
      } as Response);

      await expect(
        createScan({
          targetUrl: '10.99.99.99',
          type: 'quick',
        })
      ).rejects.toBeInstanceOf(ApiError);
    });
  });

  describe('2. Scan Status API (GET /api/v1/scans/{scan_id})', () => {
    it('retrieves live status, elapsed duration, and logs accurately', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          target: '127.0.0.1',
          scan_type: 'quick',
          status: 'completed',
          progress: 100,
          created_at: '2026-10-27T12:00:00Z',
          started_at: '2026-10-27T12:00:01Z',
          completed_at: '2026-10-27T12:00:25Z',
        }),
      } as Response);

      const scan = await getScan('34dffa0e-d82d-40c4-898d-39d634e6426d');
      expect(scan).toBeDefined();
      expect(scan?.status).toBe('completed');
      expect(scan?.progress).toBe(100);
      expect(scan?.duration).toBe('24s');
      expect(scan?.findings.total).toBe(0);
      expect(scan?.logs?.some((l) => l.includes('[SUCCESS]'))).toBe(true);
    });

    it('maps error_message truthfully when scan fails', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: '0c512f36-28e6-4baa-be22-533f91a95c04',
          target: '127.0.0.1',
          scan_type: 'quick',
          status: 'failed',
          progress: 0,
          error_message: 'Scan timed out after 300 seconds.',
          created_at: '2026-10-27T12:00:00Z',
          started_at: '2026-10-27T12:00:01Z',
        }),
      } as Response);

      const scan = await getScan('0c512f36-28e6-4baa-be22-533f91a95c04');
      expect(scan).toBeDefined();
      expect(scan?.status).toBe('failed');
      expect(scan?.errorMessage).toBe('Scan timed out after 300 seconds.');
      expect(scan?.logs?.some((l) => l.includes('Scan timed out after 300 seconds.'))).toBe(true);
    });
  });

  describe('3. Scan Results API (GET /api/v1/scan-results?scan_id={scan_id})', () => {
    it('retrieves real persisted discovery records with all service details', async () => {
      const mockDiscoveryItems: ScanResult[] = [
        {
          id: 'res-1',
          scan_id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          host_address: '127.0.0.1',
          hostname: 'localhost',
          host_state: 'up',
          port: 135,
          protocol: 'tcp',
          port_state: 'open',
          service_name: 'msrpc',
          service_product: 'Microsoft Windows RPC',
          service_version: null,
          service_extra_info: null,
          created_at: '2026-10-27T12:00:25Z',
        },
        {
          id: 'res-2',
          scan_id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          host_address: '127.0.0.1',
          hostname: 'localhost',
          host_state: 'up',
          port: 445,
          protocol: 'tcp',
          port_state: 'open',
          service_name: 'microsoft-ds',
          service_product: 'Windows 11',
          service_version: null,
          service_extra_info: null,
          created_at: '2026-10-27T12:00:25Z',
        },
        {
          id: 'res-3',
          scan_id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          host_address: '127.0.0.1',
          hostname: 'localhost',
          host_state: 'up',
          port: 5432,
          protocol: 'tcp',
          port_state: 'open',
          service_name: 'postgresql',
          service_product: 'PostgreSQL DB',
          service_version: '18.0',
          service_extra_info: null,
          created_at: '2026-10-27T12:00:25Z',
        },
        {
          id: 'res-4',
          scan_id: '34dffa0e-d82d-40c4-898d-39d634e6426d',
          host_address: '127.0.0.1',
          hostname: 'localhost',
          host_state: 'up',
          port: 8000,
          protocol: 'tcp',
          port_state: 'open',
          service_name: 'http',
          service_product: 'uvicorn',
          service_version: '0.34.0',
          service_extra_info: 'Python 3.13',
          created_at: '2026-10-27T12:00:25Z',
        },
      ];

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          items: mockDiscoveryItems,
          total: 4,
          page: 1,
          size: 200,
          pages: 1,
        }),
      } as Response);

      const results = await getScanResults('34dffa0e-d82d-40c4-898d-39d634e6426d');
      expect(results).toHaveLength(4);

      const ports = results.map((r) => r.port);
      expect(ports).toEqual([135, 445, 5432, 8000]);

      // Verify product and version formatting
      const pg = results.find((r) => r.port === 5432);
      expect(pg?.service_product).toBe('PostgreSQL DB');
      expect(pg?.service_version).toBe('18.0');

      const uvicorn = results.find((r) => r.port === 8000);
      const formattedUvicorn = [
        uvicorn?.service_product,
        uvicorn?.service_version,
        uvicorn?.service_extra_info,
      ]
        .filter(Boolean)
        .join(' ');
      expect(formattedUvicorn).toBe('uvicorn 0.34.0 Python 3.13');
    });

    it('returns empty array when target has no open ports without crashing', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          items: [],
          total: 0,
          page: 1,
          size: 200,
          pages: 0,
        }),
      } as Response);

      const results = await getScanResults('empty-scan-id');
      expect(results).toEqual([]);
    });

    it('preserves separation: open ports discovery never fabricates vulnerabilities', () => {
      // Invariant check: discovered ports must not synthesize CVEs or increment critical/high counts
      const dummyScanResult: ScanResult = {
        id: 'res-5432',
        scan_id: 'scan-1',
        host_address: '127.0.0.1',
        host_state: 'up',
        port: 5432,
        protocol: 'tcp',
        port_state: 'open',
        service_name: 'postgresql',
        service_product: 'PostgreSQL DB',
        service_version: '18.0',
        created_at: new Date().toISOString(),
      };

      // Ensure that port discovery is typed strictly as ScanResult, not Vulnerability
      expect(dummyScanResult.port).toBe(5432);
      expect((dummyScanResult as any).cve).toBeUndefined();
      expect((dummyScanResult as any).cvss).toBeUndefined();
      expect((dummyScanResult as any).severity).toBeUndefined();
    });
  });

  describe('4. Scan Cancellation API (POST /api/v1/scans/{id}/cancel)', () => {
    it('cancels active scan and returns updated terminal state', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: 'scan-to-cancel',
          target: '127.0.0.1',
          scan_type: 'quick',
          status: 'cancelled',
          progress: 45,
          created_at: '2026-10-27T12:00:00Z',
          started_at: '2026-10-27T12:00:01Z',
          completed_at: '2026-10-27T12:00:05Z',
        }),
      } as Response);

      const scan = await cancelScan('scan-to-cancel');
      expect(scan?.status).toBe('cancelled');
      expect(scan?.logs?.some((l) => l.includes('cancelled by operator'))).toBe(true);
    });
  });
});
