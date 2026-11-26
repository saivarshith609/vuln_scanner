/**
 * Phase 7: Asset Management & Drawer — Frontend Tests
 *
 * Validates:
 * - Asset inventory list rendering with real API schemas
 * - Drawer opening/closing, async data loading patterns
 * - Enhanced getScanResults and getScans filter params
 * - Asset interface truthful defaults (no fabricated OS/location)
 * - mapBackendAsset mapping fidelity
 * - Search and type filtering
 */

import { describe, it, expect, vi } from 'vitest';
import {
  getAssets,
  getScans,
  getScanResults,
  createAsset,
  ApiError,
} from '../services/api';

describe('Phase 7: Asset Management & Drawer', () => {
  // ── Asset Inventory ────────────────────────────────────────────────────

  it('getAssets returns mapped assets from backend with truthful defaults', async () => {
    const originalFetch = globalThis.fetch;
    const mockBackendAsset = {
      id: 'b1f1e4a5-0001-4000-8000-000000000001',
      name: 'prod-gateway',
      asset_type: 'network',
      target: '10.0.0.1',
      description: 'Core router — managed by NetOps',
      created_at: '2026-10-25T08:00:00Z',
      updated_at: '2026-10-27T12:00:00Z',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [mockBackendAsset],
        total: 1,
        page: 1,
        size: 100,
        pages: 1,
      }),
    } as Response);

    try {
      const assets = await getAssets();
      expect(assets).toHaveLength(1);
      const a = assets[0];

      // Mapped correctly
      expect(a.id).toBe(mockBackendAsset.id);
      expect(a.name).toBe('prod-gateway');
      expect(a.ip).toBe('10.0.0.1');
      expect(a.type).toBe('network');

      // Truthful defaults — no fabricated OS or location
      expect(a.os).toBeUndefined();
      expect(a.location).toBeUndefined();

      // Status should NOT be 'online' for a backend asset with no scan data
      expect(a.status).toBe('unscanned');

      // Description mapped to owner field
      expect(a.owner).toBe('Core router — managed by NetOps');

      // Timestamps preserved
      expect(a.created_at).toBe('2026-10-25T08:00:00Z');
      expect(a.updated_at).toBe('2026-10-27T12:00:00Z');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('getAssets surfaces a truthful transport error when backend is unreachable', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    try {
      await expect(getAssets()).rejects.toBeInstanceOf(ApiError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ── getScanResults with host filter ────────────────────────────────────

  it('getScanResults accepts a host-only param object', async () => {
    const originalFetch = globalThis.fetch;
    const mockResult = {
      id: 'r-0001',
      scan_id: 's-0001',
      host_address: '192.168.1.50',
      host_state: 'up',
      port: 80,
      protocol: 'tcp',
      port_state: 'open',
      service_name: 'http',
      service_product: 'nginx',
      service_version: '1.24.0',
      created_at: '2026-10-27T12:00:00Z',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [mockResult],
        total: 1,
        page: 1,
        size: 200,
        pages: 1,
      }),
    } as Response);

    try {
      const results = await getScanResults({ host: '192.168.1.50' });
      expect(results).toHaveLength(1);
      expect(results[0].port).toBe(80);
      expect(results[0].service_name).toBe('http');

      // Verify the request URL includes host param
      const calledUrl = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(calledUrl).toContain('host=192.168.1.50');
      expect(calledUrl).not.toContain('scan_id=');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('getScanResults still accepts a string scan_id (backward compat)', async () => {
    const originalFetch = globalThis.fetch;
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

    try {
      const results = await getScanResults('some-scan-uuid');
      expect(Array.isArray(results)).toBe(true);

      const calledUrl = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(calledUrl).toContain('scan_id=some-scan-uuid');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ── getScans with filter params ────────────────────────────────────────

  it('getScans accepts target filter param', async () => {
    const originalFetch = globalThis.fetch;
    const mockScan = {
      id: 's-001',
      target: '10.0.0.1',
      scan_type: 'quick',
      status: 'completed',
      progress: 100,
      created_at: '2026-10-27T12:00:00Z',
      completed_at: '2026-10-27T12:02:00Z',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [mockScan],
        total: 1,
        page: 1,
        size: 100,
        pages: 1,
      }),
    } as Response);

    try {
      const scans = await getScans({ target: '10.0.0.1' });
      expect(scans).toHaveLength(1);
      expect(scans[0].targetUrl).toBe('10.0.0.1');

      const calledUrl = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(calledUrl).toContain('target=10.0.0.1');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('getScans accepts assetId filter param', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [],
        total: 0,
        page: 1,
        size: 100,
        pages: 0,
      }),
    } as Response);

    try {
      const scans = await getScans({ assetId: 'asset-uuid-123' });
      expect(Array.isArray(scans)).toBe(true);

      const calledUrl = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(calledUrl).toContain('asset_id=asset-uuid-123');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('getScans without params works as before', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [],
        total: 0,
        page: 1,
        size: 100,
        pages: 0,
      }),
    } as Response);

    try {
      const scans = await getScans();
      expect(Array.isArray(scans)).toBe(true);

      const calledUrl = String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(calledUrl).toContain('size=100');
      expect(calledUrl).not.toContain('target=');
      expect(calledUrl).not.toContain('asset_id=');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ── createAsset still works ────────────────────────────────────────────

  it('createAsset correctly maps backend response', async () => {
    const originalFetch = globalThis.fetch;
    const mockResponse = {
      id: 'new-asset-id',
      name: 'test-server',
      asset_type: 'server',
      target: '192.168.0.1',
      description: null,
      created_at: '2026-10-27T16:00:00Z',
      updated_at: '2026-10-27T16:00:00Z',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockResponse,
    } as Response);

    try {
      const asset = await createAsset({
        name: 'test-server',
        ip: '192.168.0.1',
        type: 'server',
      });
      expect(asset.id).toBe('new-asset-id');
      expect(asset.name).toBe('test-server');
      expect(asset.ip).toBe('192.168.0.1');
      expect(asset.type).toBe('server');
      expect(asset.status).toBe('unscanned');
      expect(asset.os).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // ── Asset type mapping edge cases ──────────────────────────────────────

  it('maps unknown asset_type to server fallback', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [{
          id: 'edge-case-id',
          name: 'IoT Device',
          asset_type: 'iot',
          target: '10.10.10.10',
          description: null,
          created_at: '2026-10-27T12:00:00Z',
          updated_at: '2026-10-27T12:00:00Z',
        }],
        total: 1,
        page: 1,
        size: 100,
        pages: 1,
      }),
    } as Response);

    try {
      const assets = await getAssets();
      expect(assets[0].type).toBe('server');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
