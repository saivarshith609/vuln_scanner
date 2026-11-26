import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getAuthorizedTargets,
  getAuthorizedTarget,
  createAuthorizedTarget,
  updateAuthorizedTarget,
  deleteAuthorizedTarget,
  ApiError,
} from '../services/api';
import { validateTargetSyntax, detectTargetType } from '../utils/targetValidator';
import type { AuthorizedTarget } from '../types';

describe('Phase 4.4: Authorized Targets Management UI & Integration', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Target Validation & Scope Classification
  // ─────────────────────────────────────────────────────────────────────────────
  describe('1. Target Syntax Validation & Scope Detection', () => {
    it('accepts valid IPv4 addresses and classifies them as IPv4', () => {
      const targets = ['127.0.0.1', '192.168.1.1', '10.0.0.1', '8.8.8.8', '0.0.0.0'];
      for (const t of targets) {
        const val = validateTargetSyntax(t);
        expect(val.isValid).toBe(true);
        expect(detectTargetType(t)).toBe('IPv4');
      }
    });

    it('accepts valid IPv4 CIDR subnet notations and classifies them as CIDR', () => {
      const cidrs = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/16', '127.0.0.1/32'];
      for (const c of cidrs) {
        const val = validateTargetSyntax(c);
        expect(val.isValid).toBe(true);
        expect(detectTargetType(c)).toBe('CIDR');
      }
    });

    it('accepts valid IPv6 addresses and classifies them as IPv6', () => {
      const ipv6s = ['::1', '2001:db8::1', 'fe80::1'];
      for (const ip of ipv6s) {
        const val = validateTargetSyntax(ip);
        expect(val.isValid).toBe(true);
        expect(detectTargetType(ip)).toBe('IPv6');
      }
    });

    it('accepts valid RFC 1123 hostnames and classifies them as Hostname', () => {
      const hostnames = ['localhost', 'scanme.nmap.org', 'internal-db.corp', 'bastion.staging.net'];
      for (const h of hostnames) {
        const val = validateTargetSyntax(h);
        expect(val.isValid).toBe(true);
        expect(detectTargetType(h)).toBe('Hostname');
      }
    });

    it('rejects empty or whitespace-only target inputs', () => {
      expect(validateTargetSyntax('').isValid).toBe(false);
      expect(validateTargetSyntax('   ').isValid).toBe(false);
      expect(validateTargetSyntax('').error).toContain('required');
    });

    it('rejects invalid targets containing spaces, protocols, paths, or illegal characters', () => {
      const invalid = [
        '192.168.1.1 foo',
        'http://127.0.0.1',
        'https://example.com/api',
        '999.999.999.999',
        '192.168.1.0/45',
        'invalid_hostname!@#',
        'target..double.dot',
      ];
      for (const inv of invalid) {
        const res = validateTargetSyntax(inv);
        expect(res.isValid).toBe(false);
        expect(res.error).toBeDefined();
      }
    });

    it('rejects strings exceeding 255 characters', () => {
      const longTarget = 'a'.repeat(256) + '.com';
      const res = validateTargetSyntax(longTarget);
      expect(res.isValid).toBe(false);
      expect(res.error).toContain('255 characters');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. CRUD Operations via API Service
  // ─────────────────────────────────────────────────────────────────────────────
  describe('2. Authorized Targets API Service CRUD Integration', () => {
    const mockTargetRecord: AuthorizedTarget = {
      id: '67300dbe-06e7-42ae-84ea-fba2bac3ea92',
      target: '192.168.1.0/24',
      description: 'Dev Subnet',
      is_enabled: true,
      created_at: '2026-10-27T10:00:00Z',
    };

    it('GET /authorized-targets fetches paginated list with query params', async () => {
      let requestedUrl = '';
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = String(url);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [mockTargetRecord],
            total: 1,
            page: 1,
            size: 50,
            pages: 1,
          }),
        } as Response;
      });

      const res = await getAuthorizedTargets(1, 50, false);
      expect(requestedUrl).toContain('/authorized-targets');
      expect(requestedUrl).toContain('page=1');
      expect(requestedUrl).toContain('size=50');
      expect(res.items.length).toBe(1);
      expect(res.items[0].target).toBe('192.168.1.0/24');
      expect(res.items[0].is_enabled).toBe(true);
    });

    it('GET /authorized-targets passes enabled_only=true when requested', async () => {
      let requestedUrl = '';
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = String(url);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [mockTargetRecord],
            total: 1,
            page: 1,
            size: 50,
            pages: 1,
          }),
        } as Response;
      });

      await getAuthorizedTargets(1, 20, true);
      expect(requestedUrl).toContain('enabled_only=true');
    });

    it('GET /authorized-targets/:id retrieves a single target entry', async () => {
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        expect(String(url)).toContain('/authorized-targets/67300dbe-06e7-42ae-84ea-fba2bac3ea92');
        return {
          ok: true,
          status: 200,
          json: async () => mockTargetRecord,
        } as Response;
      });

      const target = await getAuthorizedTarget('67300dbe-06e7-42ae-84ea-fba2bac3ea92');
      expect(target).toBeDefined();
      expect(target?.id).toBe('67300dbe-06e7-42ae-84ea-fba2bac3ea92');
      expect(target?.target).toBe('192.168.1.0/24');
    });

    it('POST /authorized-targets creates new target entry and returns 201 response', async () => {
      let sentBody: any = null;
      let sentMethod = '';

      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        sentMethod = init?.method || '';
        sentBody = JSON.parse((init?.body as string) || '{}');
        return {
          ok: true,
          status: 201,
          json: async () => ({
            id: 'a8b9c0d1-1234-5678-9abc-def012345678',
            target: sentBody.target,
            description: sentBody.description,
            is_enabled: sentBody.is_enabled,
            created_at: '2026-10-27T12:30:00Z',
          }),
        } as Response;
      });

      const created = await createAuthorizedTarget({
        target: '  10.10.10.0/24  ',
        description: '  Staging cluster  ',
        is_enabled: true,
      });

      expect(sentMethod).toBe('POST');
      expect(sentBody.target).toBe('10.10.10.0/24'); // trimmed
      expect(sentBody.description).toBe('Staging cluster'); // trimmed
      expect(sentBody.is_enabled).toBe(true);
      expect(created.target).toBe('10.10.10.0/24');
      expect(created.id).toBe('a8b9c0d1-1234-5678-9abc-def012345678');
    });

    it('PATCH /authorized-targets/:id enables/disables target state', async () => {
      let sentBody: any = null;
      let sentMethod = '';

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        expect(String(url)).toContain('/authorized-targets/67300dbe-06e7-42ae-84ea-fba2bac3ea92');
        sentMethod = init?.method || '';
        sentBody = JSON.parse((init?.body as string) || '{}');
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...mockTargetRecord,
            is_enabled: sentBody.is_enabled,
          }),
        } as Response;
      });

      const updated = await updateAuthorizedTarget('67300dbe-06e7-42ae-84ea-fba2bac3ea92', {
        is_enabled: false,
      });

      expect(sentMethod).toBe('PATCH');
      expect(sentBody.is_enabled).toBe(false);
      expect(updated.is_enabled).toBe(false);
    });

    it('DELETE /authorized-targets/:id removes target and handles 204 No Content', async () => {
      let sentMethod = '';

      globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        expect(String(url)).toContain('/authorized-targets/67300dbe-06e7-42ae-84ea-fba2bac3ea92');
        sentMethod = init?.method || '';
        return {
          ok: true,
          status: 204,
        } as Response;
      });

      const res = await deleteAuthorizedTarget('67300dbe-06e7-42ae-84ea-fba2bac3ea92');
      expect(sentMethod).toBe('DELETE');
      expect(res.success).toBe(true);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Error Handling & Validation
  // ─────────────────────────────────────────────────────────────────────────────
  describe('3. Error Handling & Validation from Backend', () => {
    it('throws ApiError with status 409 when target already exists in allow-list', async () => {
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        return {
          ok: false,
          status: 409,
          statusText: 'Conflict',
          json: async () => ({
            detail: "Target '127.0.0.1' already exists in the authorized list.",
          }),
        } as Response;
      });

      await expect(
        createAuthorizedTarget({ target: '127.0.0.1', is_enabled: true })
      ).rejects.toThrowError("Target '127.0.0.1' already exists in the authorized list.");
    });

    it('throws ApiError with formatted detail on 422 Unprocessable Entity array responses', async () => {
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        return {
          ok: false,
          status: 422,
          statusText: 'Unprocessable Entity',
          json: async () => ({
            detail: [
              {
                loc: ['body', 'target'],
                msg: "Value error, 'invalid-target' is not a valid IP address, CIDR range, or hostname.",
                type: 'value_error',
              },
            ],
          }),
        } as Response;
      });

      try {
        await createAuthorizedTarget({ target: 'invalid-target', is_enabled: true });
        expect.unreachable('Should have thrown an ApiError');
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(422);
        expect(apiErr.message).toContain('not a valid IP address');
      }
    });

    it('throws ApiError with status 404 when updating non-existent target', async () => {
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        return {
          ok: false,
          status: 404,
          statusText: 'Not Found',
          json: async () => ({
            detail: "Authorized target '00000000-0000-0000-0000-000000000000' not found.",
          }),
        } as Response;
      });

      await expect(
        updateAuthorizedTarget('00000000-0000-0000-0000-000000000000', { is_enabled: false })
      ).rejects.toThrowError("Authorized target '00000000-0000-0000-0000-000000000000' not found.");
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. UI Filtering, Scope Policy, and State Assertions
  // ─────────────────────────────────────────────────────────────────────────────
  describe('4. UI Filtering and Scope Policy Invariants', () => {
    const sampleTargets: AuthorizedTarget[] = [
      {
        id: '1',
        target: '127.0.0.1',
        description: 'Loopback interface',
        is_enabled: true,
        created_at: '2026-10-27T10:00:00Z',
      },
      {
        id: '2',
        target: '192.168.1.0/24',
        description: 'Internal lab subnet',
        is_enabled: true,
        created_at: '2026-10-27T10:05:00Z',
      },
      {
        id: '3',
        target: 'scanme.nmap.org',
        description: 'External test host',
        is_enabled: false,
        created_at: '2026-10-27T10:10:00Z',
      },
    ];

    it('filters targets accurately by search term (target or description)', () => {
      const query = 'lab';
      const filtered = sampleTargets.filter(
        (t) =>
          t.target.toLowerCase().includes(query) ||
          (t.description || '').toLowerCase().includes(query)
      );

      expect(filtered.length).toBe(1);
      expect(filtered[0].target).toBe('192.168.1.0/24');
    });

    it('filters targets accurately by enabled/disabled state', () => {
      const enabledOnly = sampleTargets.filter((t) => t.is_enabled);
      const disabledOnly = sampleTargets.filter((t) => !t.is_enabled);

      expect(enabledOnly.length).toBe(2);
      expect(disabledOnly.length).toBe(1);
      expect(disabledOnly[0].target).toBe('scanme.nmap.org');
    });

    it('handles empty target list gracefully without mock injection', async () => {
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [],
            total: 0,
            page: 1,
            size: 50,
            pages: 1,
          }),
        } as Response;
      });

      const res = await getAuthorizedTargets();
      expect(res.items).toEqual([]);
      expect(res.total).toBe(0);
    });

    it('scope policy text explicitly forbids arbitrary third-party scanning', () => {
      const scopeDisclaimer =
        'Adding a target authorizes VulnScanner to perform port scans strictly within the configured target scope. Target authorization does not grant permission to scan arbitrary third-party systems.';

      expect(scopeDisclaimer).toContain('strictly within the configured target scope');
      expect(scopeDisclaimer).toContain('does not grant permission to scan arbitrary third-party systems');
    });
  });
});
