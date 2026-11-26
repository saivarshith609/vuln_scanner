import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  getAdminOverview,
  getAdminUsers,
  resetAdminUserPassword,
  updateAdminUser,
} from '../services/api';

afterEach(() => vi.unstubAllGlobals());

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status,
  headers: { 'Content-Type': 'application/json' },
});

describe('administrator control-center API client', () => {
  it('loads real overview and bounded user filters through credentialed admin endpoints', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({
        total_users: 2, active_users: 2, disabled_users: 0, online_users: 1,
        total_scans: 3, running_scans: 0, completed_scans: 3, failed_scans: 0,
        cancelled_scans: 0, total_findings: 1, findings_by_severity: { high: 1 },
        recent_discoveries: [], recent_activity: [],
        health: { backend: 'healthy', database: 'healthy', nmap: 'healthy' },
      }))
      .mockResolvedValueOnce(json({ items: [], total: 0, page: 1, size: 20, pages: 1 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(getAdminOverview()).resolves.toMatchObject({ total_users: 2 });
    await expect(getAdminUsers({ search: 'alice', role: 'user', page: 1 })).resolves.toMatchObject({ total: 0 });
    expect(fetchMock).toHaveBeenNthCalledWith(1, expect.stringContaining('/admin/overview?days=30'), expect.objectContaining({ credentials: 'include' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, expect.stringContaining('/admin/users?search=alice&role=user&page=1'), expect.objectContaining({ credentials: 'include' }));
  });

  it('sends optimistic versions for account edits and never serializes password hashes', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      id: 'user-1', full_name: 'Alice Admin', username: 'alice', email: 'alice@example.test',
      role: 'admin', is_active: true, version: 8, password_change_required: false,
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      last_login_at: null, last_activity_at: null, online: false, active_sessions: 0,
      total_scans: 0, total_findings: 0, total_reports: 0, sessions: [],
    }));
    vi.stubGlobal('fetch', fetchMock);
    await updateAdminUser('user-1', { version: 7, full_name: 'Alice Admin' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('PATCH');
    expect(init.body).toContain('"version":7');
    expect(init.body).not.toContain('password_hash');
  });

  it('submits a temporary password only to the reset endpoint and does not retain it in the response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ success: true, message: 'Temporary password set.' }));
    vi.stubGlobal('fetch', fetchMock);
    const temporary = 'Temporary!Secret456';
    const response = await resetAdminUserPassword('user-1', temporary, temporary);
    expect(response.message).not.toContain(temporary);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/admin/users/user-1/reset-password'),
      expect.objectContaining({ method: 'POST', credentials: 'include', body: expect.stringContaining(temporary) }),
    );
  });
});
