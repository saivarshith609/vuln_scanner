// @vitest-environment jsdom

import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const authApi = vi.hoisted(() => ({
  getApiHealth: vi.fn(),
  getAuthSession: vi.fn(),
  createAuthSession: vi.fn(),
  loginAdministrator: vi.fn(),
  endAuthSession: vi.fn(),
  logoutUser: vi.fn(),
  loginUser: vi.fn(),
  registerUser: vi.fn(),
  changePassword: vi.fn(),
}));

vi.mock('../services/api', () => ({
  API_BASE_URL: 'http://localhost:8000/api/v1',
  getApiHealth: authApi.getApiHealth,
  getAuthSession: authApi.getAuthSession,
  createAuthSession: authApi.createAuthSession,
  loginAdministrator: authApi.loginAdministrator,
  endAuthSession: authApi.endAuthSession,
  logoutUser: authApi.logoutUser,
  loginUser: authApi.loginUser,
  registerUser: authApi.registerUser,
  changePassword: authApi.changePassword,
}));

import { AuthGate } from '../components/auth/AuthGate';
import { useAuth } from '../components/auth/authContext';

const session = {
  authenticated: true,
  method: 'session' as const,
  expires_at: '2026-10-28T12:00:00Z',
};

function SessionIdentity() {
  const { user, logout } = useAuth();
  return <div><span>Current role: {user?.role}</span><button onClick={() => void logout()}>Log out test account</button></div>;
}

describe('Phase 15 authentication UI regression', () => {
  beforeEach(() => {
    authApi.getApiHealth.mockReset().mockResolvedValue({ status: 'healthy', application: 'VulnScanner API', version: '1.0.0' });
    authApi.getAuthSession.mockReset();
    authApi.createAuthSession.mockReset();
    authApi.loginAdministrator.mockReset();
    authApi.endAuthSession.mockReset().mockResolvedValue(undefined);
    authApi.logoutUser.mockReset().mockResolvedValue(undefined);
    authApi.loginUser.mockReset();
    authApi.registerUser.mockReset();
    authApi.changePassword.mockReset();
    window.history.replaceState({}, '', '/login');
  });

  it('keeps protected UI hidden when the server rejects the session', async () => {
    authApi.getAuthSession.mockRejectedValueOnce(new Error('Authentication required'));

    render(<AuthGate><div>Protected operations</div></AuthGate>);

    expect(screen.getByText('Checking secure session')).toBeInTheDocument();
    expect(await screen.findByText('Administrator sign in')).toBeInTheDocument();
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Platform API key')).not.toBeInTheDocument();
  });

  it('signs an authorized administrator in with database credentials and redirects to admin', async () => {
    const user = userEvent.setup();
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem');
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    authApi.getAuthSession.mockRejectedValueOnce(new Error('Authentication required'));
    authApi.loginAdministrator.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'admin-1', full_name: 'Security Admin', username: 'security-admin', email: 'admin@example.test',
        role: 'admin', is_active: true,
      },
    });

    render(<AuthGate><div>Protected operations</div></AuthGate>);
    await user.type(await screen.findByLabelText('Administrator username or email'), 'admin@example.test');
    await user.type(screen.getByLabelText('Administrator password'), 'StrongPassword!42');
    await user.click(screen.getByRole('button', { name: 'Sign In as Administrator' }));

    expect(await screen.findByText('Protected operations')).toBeInTheDocument();
    expect(authApi.loginAdministrator).toHaveBeenCalledWith('admin@example.test', 'StrongPassword!42');
    expect(window.location.pathname).toBe('/admin');
    expect(storageSpy).not.toHaveBeenCalled();
    expect(logSpy).not.toHaveBeenCalled();
  });

  it('shows the backend denial when a normal account uses administrator sign in', async () => {
    const user = userEvent.setup();
    authApi.getAuthSession.mockRejectedValueOnce(new Error('Authentication required'));
    authApi.loginAdministrator.mockRejectedValueOnce(
      Object.assign(new Error('Administrator privileges are required.'), { status: 403 }),
    );
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    await user.type(await screen.findByLabelText('Administrator username or email'), 'ordinary-user');
    await user.type(screen.getByLabelText('Administrator password'), 'StrongPassword!42');
    await user.click(screen.getByRole('button', { name: 'Sign In as Administrator' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Administrator privileges are required.');
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
  });

  it('keeps administrator credentials on the normal form and surfaces the role mismatch', async () => {
    const user = userEvent.setup();
    authApi.getAuthSession.mockRejectedValueOnce(new Error('Authentication required'));
    authApi.loginUser.mockRejectedValueOnce(
      Object.assign(new Error('Use the administrator sign-in form for this account.'), { status: 403 }),
    );
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    await user.type(await screen.findByLabelText('Username or email'), 'database_admin');
    await user.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await user.click(screen.getByRole('button', { name: /^Sign In$/ }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Use the administrator sign-in form');
    expect(authApi.loginUser).toHaveBeenCalledWith('database_admin', 'StrongPassword!42');
    expect(authApi.loginAdministrator).not.toHaveBeenCalled();
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
  });

  it('restores an administrator session after refresh without resubmitting credentials', async () => {
    window.history.replaceState({}, '', '/admin');
    authApi.getAuthSession.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'admin-1', full_name: 'Security Admin', username: 'security-admin', email: 'admin@example.test',
        role: 'admin', is_active: true,
      },
    });
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    expect(await screen.findByText('Protected operations')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/admin');
    expect(authApi.loginAdministrator).not.toHaveBeenCalled();
  });

  it('restores the server-verified normal role after refresh', async () => {
    window.history.replaceState({}, '', '/');
    authApi.getAuthSession.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'user-1', full_name: 'Normal User', username: 'normal-user', email: 'normal@example.test',
        role: 'user', is_active: true,
      },
    });
    render(<AuthGate><SessionIdentity /></AuthGate>);
    expect(await screen.findByText('Current role: user')).toBeInTheDocument();
  });

  it('fails closed when a session response omits its verified user identity', async () => {
    authApi.getAuthSession.mockResolvedValueOnce(session);
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    expect(await screen.findByText('Administrator sign in')).toBeInTheDocument();
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid session identity');
    expect(authApi.endAuthSession).toHaveBeenCalledOnce();
  });

  it('does not retain an administrator role after logout and normal-user login', async () => {
    const browser = userEvent.setup();
    window.history.replaceState({}, '', '/admin');
    authApi.getAuthSession.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'admin-1', full_name: 'Security Admin', username: 'security-admin', email: 'admin@example.test',
        role: 'admin', is_active: true,
      },
    });
    authApi.loginUser.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'user-1', full_name: 'Normal User', username: 'normal-user', email: 'normal@example.test',
        role: 'user', is_active: true,
      },
    });

    render(<AuthGate><SessionIdentity /></AuthGate>);
    expect(await screen.findByText('Current role: admin')).toBeInTheDocument();
    await browser.click(screen.getByRole('button', { name: 'Log out test account' }));
    await browser.type(await screen.findByLabelText('Username or email'), 'normal-user');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: /^Sign In$/ }));

    expect(await screen.findByText('Current role: user')).toBeInTheDocument();
    expect(authApi.logoutUser).toHaveBeenCalledOnce();
    expect(authApi.loginUser).toHaveBeenCalledWith('normal-user', 'StrongPassword!42');
    expect(window.location.pathname).toBe('/');
  });

  it('removes protected UI and clears the credential field on session expiry', async () => {
    authApi.getAuthSession.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'user-1', full_name: 'Normal User', username: 'normal-user', email: 'normal@example.test',
        role: 'user', is_active: true,
      },
    });
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    expect(await screen.findByText('Protected operations')).toBeInTheDocument();

    act(() => window.dispatchEvent(new Event('vulnscanner:authentication-required')));

    expect(await screen.findByText('Administrator sign in')).toBeInTheDocument();
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Administrator username or email')).toHaveValue('');
    await waitFor(() => expect(authApi.endAuthSession).toHaveBeenCalledOnce());
  });

  it('logs an idle authenticated user out after exactly five minutes', async () => {
    vi.useFakeTimers();
    try {
      authApi.getAuthSession.mockResolvedValueOnce({
        ...session,
        user: { id: 'user-1', full_name: 'Normal User', username: 'normal-user', email: 'normal@example.test', role: 'user', is_active: true },
      });
      render(<AuthGate><div>Protected operations</div></AuthGate>);
      await act(async () => { await Promise.resolve(); });
      expect(screen.getByText('Protected operations')).toBeInTheDocument();
      await act(async () => { vi.advanceTimersByTime(299_999); });
      expect(screen.getByText('Protected operations')).toBeInTheDocument();
      await act(async () => { vi.advanceTimersByTime(1); });
      expect(screen.getByText('Sign in to VulnScanner')).toBeInTheDocument();
      expect(authApi.logoutUser).toHaveBeenCalledOnce();
      expect(screen.getByRole('status')).toHaveTextContent('5 minutes of inactivity');
    } finally {
      vi.useRealTimers();
    }
  });

  it('resets the idle timer when an active user interacts with the page', async () => {
    vi.useFakeTimers();
    try {
      authApi.getAuthSession.mockResolvedValueOnce({
        ...session,
        user: { id: 'user-1', full_name: 'Normal User', username: 'normal-user', email: 'normal@example.test', role: 'user', is_active: true },
      });
      render(<AuthGate><div>Protected operations</div></AuthGate>);
      await act(async () => { await Promise.resolve(); });
      expect(screen.getByText('Protected operations')).toBeInTheDocument();
      await act(async () => { vi.advanceTimersByTime(299_000); });
      act(() => window.dispatchEvent(new Event('keydown')));
      await act(async () => { vi.advanceTimersByTime(299_999); });
      expect(screen.getByText('Protected operations')).toBeInTheDocument();
      await act(async () => { vi.advanceTimersByTime(1); });
      expect(screen.getByText('Sign in to VulnScanner')).toBeInTheDocument();
      expect(authApi.logoutUser).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('blocks the application shell until an administrator-reset credential is changed', async () => {
    const user = userEvent.setup();
    authApi.getAuthSession.mockResolvedValueOnce({
      ...session,
      user: {
        id: 'user-1', full_name: 'Reset User', username: 'reset-user', email: 'reset@example.test',
        role: 'user', is_active: true, credential_change_required: true,
      },
    });
    authApi.changePassword.mockResolvedValueOnce({ changed: true, reauthentication_required: true });
    render(<AuthGate><div>Protected operations</div></AuthGate>);
    expect(await screen.findByText('Change temporary password')).toBeInTheDocument();
    expect(screen.queryByText('Protected operations')).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('Temporary password'), 'Temporary!Secret456');
    await user.type(screen.getByLabelText('New password'), 'Replacement!Secret789');
    await user.type(screen.getByLabelText('Confirm new password'), 'Replacement!Secret789');
    await user.click(screen.getByRole('button', { name: 'Change password' }));
    await waitFor(() => expect(authApi.changePassword).toHaveBeenCalled());
    expect(await screen.findByText('Administrator sign in')).toBeInTheDocument();
  });
});
