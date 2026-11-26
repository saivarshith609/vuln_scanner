// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest';
import { loginAdministrator, loginUser, logoutUser, registerUser } from '../services/api';

const profile = { id: 'user-1', full_name: 'Alice', username: 'alice', email: 'alice@example.com', role: 'user', is_active: true };

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'vulnscanner_csrf=; Max-Age=0; path=/';
});

describe('user authentication API client', () => {
  it('registers and logs in through credentialed requests without storing secrets', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(profile), { status: 201, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: true, method: 'session', expires_at: null, user: profile }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const payload = { full_name: 'Alice', username: 'alice', email: 'alice@example.com', password: 'StrongPassword!42', confirm_password: 'StrongPassword!42' };
    await registerUser(payload);
    await loginUser('alice', payload.password);
    expect(fetchMock).toHaveBeenNthCalledWith(1, expect.stringContaining('/auth/register'), expect.objectContaining({ method: 'POST', credentials: 'include', body: JSON.stringify(payload) }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, expect.stringContaining('/auth/login'), expect.objectContaining({ method: 'POST', credentials: 'include' }));
    expect(localStorage.length).toBe(0);
  });

  it('sends the double-submit CSRF token for authenticated logout', async () => {
    document.cookie = 'vulnscanner_csrf=csrf-token-123; path=/';
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await logoutUser();
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/auth/logout'), expect.objectContaining({
      method: 'POST', credentials: 'include', headers: expect.objectContaining({ 'X-CSRF-Token': 'csrf-token-123' }),
    }));
  });

  it('keeps normal and administrator credentials on their dedicated endpoints', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: true, method: 'session', expires_at: null, user: profile }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: true, method: 'session', expires_at: null, user: { ...profile, role: 'admin' } }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);

    await loginUser('normal', 'StrongPassword!42');
    await loginAdministrator('admin', 'StrongPassword!42');

    expect(fetchMock).toHaveBeenNthCalledWith(1, expect.stringContaining('/auth/login'), expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ identifier: 'normal', password: 'StrongPassword!42' }),
    }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, expect.stringContaining('/auth/admin/login'), expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ identifier: 'admin', password: 'StrongPassword!42' }),
    }));
  });
});
