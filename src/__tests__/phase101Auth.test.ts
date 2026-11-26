import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, createAuthSession, endAuthSession, getApiHealth, getAuthSession, getDashboard, loginAdministrator } from '../services/api';

afterEach(() => vi.unstubAllGlobals());

describe('Phase 10.1 browser authentication', () => {
  it('submits administrator credentials to the role-enforcing database login endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      authenticated: true,
      method: 'session',
      expires_at: '2026-10-28T02:00:00Z',
      user: { id: 'admin-1', username: 'security-admin', role: 'admin', is_active: true },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(loginAdministrator('security-admin', 'StrongPassword!42')).resolves.toMatchObject({
      authenticated: true,
      user: { role: 'admin' },
    });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/auth/admin/login'),
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({ identifier: 'security-admin', password: 'StrongPassword!42' }),
      }),
    );
  });

  it('exchanges an in-memory API key for a credentialed session request', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      authenticated: true,
      method: 'session',
      expires_at: '2026-10-28T02:00:00Z',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const rawKey = `vsec_live_${'a1'.repeat(32)}`;
    const result = await createAuthSession(rawKey);
    expect(result.authenticated).toBe(true);
    expect(JSON.stringify(result)).not.toContain(rawKey);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/auth/session'),
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        headers: expect.objectContaining({ 'X-API-Key': rawKey }),
      }),
    );
  });

  it('keeps local Strict-cookie login and dashboard requests on the localhost site', async () => {
    let sessionCookieAccepted = false;
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const requestUrl = new URL(String(input));
      const isCredentialed = init?.credentials === 'include';
      const isSameSiteAsVite = requestUrl.hostname === 'localhost';

      if (requestUrl.pathname.endsWith('/auth/session') && init?.method === 'POST') {
        sessionCookieAccepted = isCredentialed && isSameSiteAsVite;
        return new Response(JSON.stringify({
          authenticated: true,
          method: 'session',
          expires_at: '2026-10-28T02:00:00Z',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      if (requestUrl.pathname.endsWith('/dashboard')) {
        if (!sessionCookieAccepted || !isCredentialed) {
          return new Response(JSON.stringify({ detail: 'Authentication required' }), {
            status: 401,
            statusText: 'Unauthorized',
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({
          total_assets: 0,
          total_scans: 0,
          active_scans: 0,
          total_vulnerabilities: 0,
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          recent_scans: [],
          recent_vulnerabilities: [],
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      throw new Error(`Unexpected request: ${requestUrl}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const rawKey = `vsec_live_${'a1'.repeat(32)}`;
    await expect(createAuthSession(rawKey)).resolves.toMatchObject({ authenticated: true });
    await expect(getDashboard()).resolves.toBeDefined();

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'http://localhost:8000/api/v1/auth/session',
      expect.objectContaining({ method: 'POST', credentials: 'include' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'http://localhost:8000/api/v1/dashboard',
      expect.objectContaining({ credentials: 'include' }),
    );
  });

  it('checks the registered health endpoint with credentials enabled', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: 'healthy', application: 'VulnScanner API', version: '1.0.0',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(getApiHealth()).resolves.toMatchObject({ status: 'healthy' });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/health',
      expect.objectContaining({ credentials: 'include' }),
    );
  });

  it('signals the authentication gate when a protected request reports an expired session', async () => {
    const browserEvents = new EventTarget();
    const expiredHandler = vi.fn();
    browserEvents.addEventListener('vulnscanner:authentication-required', expiredHandler);
    vi.stubGlobal('window', browserEvents);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Session expired' }), {
      status: 401,
      statusText: 'Unauthorized',
      headers: { 'Content-Type': 'application/json' },
    })));
    await expect(getDashboard()).rejects.toBeInstanceOf(ApiError);
    expect(expiredHandler).toHaveBeenCalledOnce();
  });

  it('treats an anonymous session check as logged out without emitting an expiry event', async () => {
    const browserEvents = new EventTarget();
    const expiredHandler = vi.fn();
    browserEvents.addEventListener('vulnscanner:authentication-required', expiredHandler);
    vi.stubGlobal('window', browserEvents);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Authentication required' }), {
      status: 401,
      statusText: 'Unauthorized',
      headers: { 'Content-Type': 'application/json' },
    })));
    await expect(getAuthSession()).rejects.toMatchObject({ status: 401 });
    expect(expiredHandler).not.toHaveBeenCalled();
  });

  it('ends the HttpOnly session through a credentialed 204 request', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(endAuthSession()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/auth/session'),
      expect.objectContaining({ method: 'DELETE', credentials: 'include' }),
    );
  });
});
