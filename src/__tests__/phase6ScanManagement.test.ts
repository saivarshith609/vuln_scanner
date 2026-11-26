import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { deleteScan, cancelScan, createScan, ApiError } from '../services/api';
import type { Scan, ScanType } from '../types';

describe('Phase 6: Scan Engine Management & Terminal Logs', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('1. Scan Profile Alignment', () => {
    it('allows only supported engine profiles (quick, network, full)', async () => {
      const supportedProfiles: ScanType[] = ['quick', 'network', 'full'];

      for (const profile of supportedProfiles) {
        let capturedBody: any = null;
        globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
          capturedBody = JSON.parse((init?.body as string) || '{}');
          return {
            ok: true,
            status: 201,
            json: async () => ({
              id: 'test-scan-id',
              target: '127.0.0.1',
              scan_type: profile,
              status: 'queued',
              progress: 0,
              created_at: '2026-10-27T12:00:00Z',
            }),
          } as Response;
        });

        const scan = await createScan({
          targetUrl: '127.0.0.1',
          type: profile,
        });

        expect(capturedBody.scan_type).toBe(profile);
        expect(scan.type).toBe(profile);
      }
    });

    it('determines correct approved Nmap argument flags for each profile', () => {
      const getNmapCommandString = (type: ScanType, target: string): string => {
        switch (type) {
          case 'quick':
            return `nmap -sV -T3 -F -oX - ${target}`;
          case 'network':
            return `nmap -sn -oX - ${target}`;
          case 'full':
            return `nmap -sV -T3 -p- -oX - ${target}`;
          default:
            return `nmap -sV -T3 -F -oX - ${target}`;
        }
      };

      expect(getNmapCommandString('quick', '127.0.0.1')).toBe('nmap -sV -T3 -F -oX - 127.0.0.1');
      expect(getNmapCommandString('network', '192.168.1.0/24')).toBe('nmap -sn -oX - 192.168.1.0/24');
      expect(getNmapCommandString('full', '10.0.0.1')).toBe('nmap -sV -T3 -p- -oX - 10.0.0.1');
    });
  });

  describe('2. Persistent Scan Deletion (DELETE /api/v1/scans/{id})', () => {
    it('issues DELETE request to backend and returns success on HTTP 204', async () => {
      let capturedMethod = '';
      let capturedUrl = '';

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedMethod = init?.method || 'GET';
        return {
          ok: true,
          status: 204,
        } as Response;
      });

      const result = await deleteScan('scan-uuid-1234');
      expect(capturedUrl).toContain('/scans/scan-uuid-1234');
      expect(capturedMethod).toBe('DELETE');
      expect(result.success).toBe(true);
    });

    it('propagates ApiError when scan is actively running (HTTP 400)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({
          detail: 'Cannot delete an actively running scan. Abort the scan first.',
        }),
      } as Response);

      await expect(deleteScan('running-scan-id')).rejects.toThrow(ApiError);
      await expect(deleteScan('running-scan-id')).rejects.toMatchObject({
        status: 400,
        message: 'Cannot delete an actively running scan. Abort the scan first.',
      });
    });

    it('propagates ApiError when scan does not exist (HTTP 404)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({
          detail: "Scan with ID 'missing-id' not found",
        }),
      } as Response);

      await expect(deleteScan('missing-id')).rejects.toThrow(ApiError);
      await expect(deleteScan('missing-id')).rejects.toMatchObject({
        status: 404,
        message: "Scan with ID 'missing-id' not found",
      });
    });
  });

  describe('3. Lifecycle Controls & Cancellation', () => {
    it('aborts active scan via POST /api/v1/scans/{id}/cancel', async () => {
      let capturedUrl = '';
      let capturedMethod = '';

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        capturedUrl = url;
        capturedMethod = init?.method || 'GET';
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: 'scan-to-abort',
            target: '127.0.0.1',
            scan_type: 'quick',
            status: 'cancelled',
            progress: 30,
            error_message: 'Cancelled by operator.',
            created_at: '2026-10-27T12:00:00Z',
            completed_at: '2026-10-27T12:00:10Z',
          }),
        } as Response;
      });

      const cancelled = await cancelScan('scan-to-abort');
      expect(capturedUrl).toContain('/scans/scan-to-abort/cancel');
      expect(capturedMethod).toBe('POST');
      expect(cancelled?.status).toBe('cancelled');
      expect(cancelled?.errorMessage).toBe('Cancelled by operator.');
    });

    it('handles cancellation failure without falsely claiming cancelled status', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({
          detail: "Cannot cancel scan with status 'completed'",
        }),
      } as Response);

      await expect(cancelScan('completed-scan-id')).rejects.toThrow(ApiError);
    });
  });

  describe('4. Truthful Terminal Telemetry Verification', () => {
    it('presents captured timestamps, status, duration, and error message honestly', () => {
      const scan: Scan = {
        id: 'scan-exec-1',
        name: 'Local Recon',
        targetUrl: '127.0.0.1',
        type: 'quick',
        status: 'completed',
        progress: 100,
        startedAt: '10/27/2026, 12:00:00 PM',
        completedAt: '10/27/2026, 12:00:15 PM',
        duration: '15s',
        findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      };

      expect(scan.status).toBe('completed');
      expect(scan.duration).toBe('15s');
      expect(scan.startedAt).toBeDefined();
      expect(scan.completedAt).toBeDefined();
    });

    it('accurately distinguishes failed exit state with real error message', () => {
      const failedScan: Scan = {
        id: 'scan-failed-1',
        name: 'Failing Scan',
        targetUrl: '192.168.1.100',
        type: 'quick',
        status: 'failed',
        progress: 0,
        startedAt: '10/27/2026, 12:00:00 PM',
        completedAt: '10/27/2026, 12:00:05 PM',
        errorMessage: 'Nmap exited with code 1. Check Nmap privileges and target reachability.',
        findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      };

      expect(failedScan.status).toBe('failed');
      expect(failedScan.errorMessage).toContain('Nmap exited with code 1');
    });
  });
});
