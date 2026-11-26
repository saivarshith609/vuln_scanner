// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDiscovery, getDiscoveryHosts } from '../services/api';

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'vulnscanner_csrf=; Max-Age=0; path=/';
});

describe('network discovery API client', () => {
  it('posts explicit CIDR discovery confirmation with credentials', async () => {
    document.cookie = 'vulnscanner_csrf=valid-csrf-token; path=/';
    const run = { id: 'discovery-1', target: '192.168.50.0/24', target_kind: 'cidr', status: 'queued', progress: 0, partial_results: false, created_at: '2026-10-28T12:00:00Z' };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(run), { status: 201, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    await createDiscovery({ target_type: 'cidr', cidr: '192.168.50.0/24', authorization_mode: 'on_demand', authorization_confirmed: true });
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/discoveries'), expect.objectContaining({
      method: 'POST', credentials: 'include',
      headers: expect.objectContaining({ 'X-CSRF-Token': 'valid-csrf-token' }),
      body: JSON.stringify({ target_type: 'cidr', cidr: '192.168.50.0/24', authorization_mode: 'on_demand', authorization_confirmed: true }),
    }));
  });

  it('initializes a missing CSRF cookie through the authenticated session endpoint', async () => {
    const run = { id: 'discovery-2', target: '192.168.29.0/24', target_kind: 'cidr', status: 'queued', progress: 0, partial_results: false, created_at: '2026-10-29T00:00:00Z' };
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/auth/session')) {
        document.cookie = 'vulnscanner_csrf=restored-csrf-token; path=/';
        return new Response(JSON.stringify({ authenticated: true, method: 'session', expires_at: null }), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        });
      }
      expect(init?.headers).toEqual(expect.objectContaining({ 'X-CSRF-Token': 'restored-csrf-token' }));
      return new Response(JSON.stringify(run), { status: 201, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);

    await createDiscovery({ target_type: 'cidr', cidr: '192.168.29.31/24', authorization_mode: 'on_demand', authorization_confirmed: true });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toBe('http://localhost:8000/api/v1/auth/session');
    expect(fetchMock.mock.calls[1][0]).toBe('http://localhost:8000/api/v1/discoveries');
  });

  it('refreshes a stale CSRF token once and retries the rejected discovery request', async () => {
    document.cookie = 'vulnscanner_csrf=stale-csrf-token; path=/';
    const run = { id: 'discovery-3', target: '192.168.29.0/24', target_kind: 'cidr', status: 'queued', progress: 0, partial_results: false, created_at: '2026-10-29T00:00:00Z' };
    let discoveryAttempts = 0;
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/auth/session')) {
        document.cookie = 'vulnscanner_csrf=fresh-csrf-token; path=/';
        return new Response(JSON.stringify({ authenticated: true, method: 'session', expires_at: null }), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        });
      }
      discoveryAttempts += 1;
      if (discoveryAttempts === 1) {
        expect(init?.headers).toEqual(expect.objectContaining({ 'X-CSRF-Token': 'stale-csrf-token' }));
        return new Response(JSON.stringify({ detail: 'CSRF validation failed' }), {
          status: 403, statusText: 'Forbidden', headers: { 'Content-Type': 'application/json' },
        });
      }
      expect(init?.headers).toEqual(expect.objectContaining({ 'X-CSRF-Token': 'fresh-csrf-token' }));
      return new Response(JSON.stringify(run), { status: 201, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);

    await createDiscovery({ target_type: 'cidr', cidr: '192.168.29.31/24', authorization_mode: 'on_demand', authorization_confirmed: true });

    expect(discoveryAttempts).toBe(2);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('encodes inventory search and authorization filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0, page: 1, size: 500, pages: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    await getDiscoveryHosts('discovery-1', { search: 'printer & lab', authorization: 'authorized' });
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain('search=printer+%26+lab');
    expect(url).toContain('authorization=authorized');
  });
});
