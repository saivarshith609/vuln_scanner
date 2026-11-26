// @vitest-environment jsdom

import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const authApi = vi.hoisted(() => ({
  getApiHealth: vi.fn(), getAuthSession: vi.fn(), loginUser: vi.fn(), registerUser: vi.fn(), createAuthSession: vi.fn(), endAuthSession: vi.fn(), logoutUser: vi.fn(),
}));
vi.mock('../services/api', () => ({ ...authApi, API_BASE_URL: 'http://localhost:8000/api/v1' }));

import { AuthGate } from '../components/auth/AuthGate';

const user = { id: 'user-1', full_name: 'Alice Operator', username: 'alice', email: 'alice@example.com', role: 'user' as const, is_active: true };
const session = { authenticated: true, method: 'session' as const, expires_at: '2026-10-28T12:00:00Z', user };

describe('persistent account authentication UI', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
    Object.values(authApi).forEach((mock) => mock.mockReset());
    authApi.getApiHealth.mockResolvedValue({ status: 'healthy', application: 'VulnScanner API', version: '1.0.0' });
    authApi.endAuthSession.mockResolvedValue(undefined);
    authApi.logoutUser.mockResolvedValue(undefined);
  });

  it('redirects a protected path to login without rendering protected content', async () => {
    window.history.replaceState({}, '', '/reports/scan-1');
    authApi.getAuthSession.mockRejectedValue(new Error('Authentication required'));
    render(<AuthGate><div>Private report</div></AuthGate>);
    expect(screen.getByText('Checking secure session')).toBeInTheDocument();
    expect(await screen.findByText('Sign in to VulnScanner')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
    expect(screen.queryByText('Private report')).not.toBeInTheDocument();
  });

  it('reports a failed health check separately from rejected credentials', async () => {
    authApi.getApiHealth.mockRejectedValueOnce(Object.assign(new Error('network failure'), { status: 0 }));
    render(<AuthGate><div>Private dashboard</div></AuthGate>);
    expect(await screen.findByText(/Unable to reach the VulnScanner API health endpoint/)).toBeInTheDocument();
    expect(screen.getByText(/http:\/\/localhost:8000\/api\/v1\/health/)).toBeInTheDocument();
    expect(authApi.getAuthSession).not.toHaveBeenCalled();
  });

  it('explains that credentials were not validated when only the login request loses connectivity', async () => {
    const browser = userEvent.setup();
    window.history.replaceState({}, '', '/login');
    authApi.getAuthSession.mockRejectedValue(Object.assign(new Error('Authentication required'), { status: 401 }));
    authApi.loginUser.mockRejectedValue(Object.assign(new Error('Unable to reach the API service.'), { status: 0 }));
    render(<AuthGate><div>Private dashboard</div></AuthGate>);
    await browser.type(await screen.findByLabelText('Username or email'), 'alice');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: 'Sign In' }));
    expect(await screen.findByText(/login request could not reach/)).toBeInTheDocument();
    expect(screen.getByText(/credentials were not validated/)).toBeInTheDocument();
  });

  it('registers with validated fields, then requires explicit login', async () => {
    const browser = userEvent.setup();
    window.history.replaceState({}, '', '/register');
    authApi.getAuthSession.mockRejectedValue(new Error('Authentication required'));
    authApi.registerUser.mockResolvedValue(user);
    render(<AuthGate><div>Private dashboard</div></AuthGate>);
    await browser.type(await screen.findByLabelText('Full name'), 'Alice Operator');
    await browser.type(screen.getByLabelText('Username'), 'alice');
    await browser.type(screen.getByLabelText('Email address'), 'alice@example.com');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.type(screen.getByLabelText('Confirm password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: 'Create Account' }));
    expect(authApi.registerUser).toHaveBeenCalledWith(expect.objectContaining({ username: 'alice', email: 'alice@example.com' }));
    expect(await screen.findByText(/Account created successfully/)).toBeInTheDocument();
    expect(screen.queryByText('Private dashboard')).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
  });

  it('accepts a 6-character strong password and rejects a 5-character password on registration', async () => {
    const browser = userEvent.setup();
    window.history.replaceState({}, '', '/register');
    authApi.getAuthSession.mockRejectedValue(new Error('Authentication required'));
    authApi.registerUser.mockResolvedValue(user);
    render(<AuthGate><div>Private dashboard</div></AuthGate>);

    await browser.type(await screen.findByLabelText('Full name'), 'Alice Operator');
    await browser.type(screen.getByLabelText('Username'), 'alice');
    await browser.type(screen.getByLabelText('Email address'), 'alice@example.com');
    await browser.type(screen.getByLabelText('Password'), 'Ab1!x');
    await browser.type(screen.getByLabelText('Confirm password'), 'Ab1!x');
    await browser.click(screen.getByRole('button', { name: 'Create Account' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Password must be 6-128 characters');
    expect(authApi.registerUser).not.toHaveBeenCalled();

    await browser.clear(screen.getByLabelText('Password'));
    await browser.clear(screen.getByLabelText('Confirm password'));
    await browser.type(screen.getByLabelText('Password'), 'Abc1!x');
    await browser.type(screen.getByLabelText('Confirm password'), 'Abc1!x');
    await browser.click(screen.getByRole('button', { name: 'Create Account' }));
    expect(authApi.registerUser).toHaveBeenCalledWith(expect.objectContaining({ password: 'Abc1!x', confirm_password: 'Abc1!x' }));
  });

  it('logs in with persisted credentials and restores the original safe path', async () => {
    const browser = userEvent.setup();
    window.history.replaceState({}, '', '/scans');
    authApi.getAuthSession.mockRejectedValue(new Error('Authentication required'));
    authApi.loginUser.mockResolvedValue(session);
    render(<AuthGate><div>Private scans</div></AuthGate>);
    await browser.type(await screen.findByLabelText('Username or email'), 'alice@example.com');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: 'Sign In' }));
    expect(authApi.loginUser).toHaveBeenCalledWith('alice@example.com', 'StrongPassword!42');
    expect(await screen.findByText('Private scans')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/scans');
  });

  it('removes protected content when the server reports an expired session', async () => {
    authApi.getAuthSession.mockResolvedValue(session);
    render(<AuthGate><div>Private dashboard</div></AuthGate>);
    expect(await screen.findByText('Private dashboard')).toBeInTheDocument();
    act(() => window.dispatchEvent(new Event('vulnscanner:authentication-required')));
    expect(await screen.findByText('Sign in to VulnScanner')).toBeInTheDocument();
    expect(screen.queryByText('Private dashboard')).not.toBeInTheDocument();
  });
});
