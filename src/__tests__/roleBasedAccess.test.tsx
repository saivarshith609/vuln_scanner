// @vitest-environment jsdom

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockedApi = vi.hoisted(() => ({
  getApiHealth: vi.fn(),
  getAuthSession: vi.fn(),
  loginUser: vi.fn(),
  loginAdministrator: vi.fn(),
  registerUser: vi.fn(),
  changePassword: vi.fn(),
  endAuthSession: vi.fn(),
  logoutUser: vi.fn(),
}));

vi.mock('../services/api', () => ({
  ...mockedApi,
  API_BASE_URL: 'http://localhost:8000/api/v1',
}));

vi.mock('../store/ScanContext', () => ({
  ScanProvider: ({ children }: { children: ReactNode }) => children,
  useScans: () => ({
    scans: [], isLoading: false, isRefreshing: false, isStale: false, error: null,
  }),
}));

vi.mock('../pages/DashboardPage', () => ({
  DashboardPage: () => <div>Mock Security Dashboard</div>,
}));

vi.mock('../pages/AdminPage', () => ({
  AdminPage: () => <div>Mock Admin Control Page</div>,
}));

vi.mock('../pages/SettingsPage', () => ({
  SettingsPage: () => <div>Mock Settings Page</div>,
}));

import App from '../App';
import { AuthContext } from '../components/auth/authContext';
import { RoleGuard } from '../components/auth/RoleGuard';
import { Sidebar } from '../layouts/Sidebar';
import type { AuthUser } from '../services/api';

const normalUser: AuthUser = {
  id: 'user-1', full_name: 'Normal User', username: 'normal', email: 'normal@example.test',
  role: 'user', is_active: true,
};

const administrator: AuthUser = {
  ...normalUser,
  id: 'admin-1', username: 'administrator', email: 'admin@example.test', role: 'admin',
};

function authenticated(user: AuthUser, child: ReactNode) {
  return <AuthContext.Provider value={{ user, logout: async () => undefined }}>{child}</AuthContext.Provider>;
}

describe('strict role-based frontend access', () => {
  beforeEach(() => window.history.replaceState({}, '', '/'));

  it('blocks direct admin-route content for a normal authenticated user', () => {
    window.history.replaceState({}, '', '/admin');
    render(authenticated(normalUser, <RoleGuard requiredRole="admin"><div>Privileged admin content</div></RoleGuard>));

    expect(screen.getByRole('alert')).toHaveTextContent('Administrator access required');
    expect(screen.queryByText('Privileged admin content')).not.toBeInTheDocument();
  });

  it('renders protected content for a backend-reported administrator role', () => {
    render(authenticated(administrator, <RoleGuard requiredRole="admin"><div>Privileged admin content</div></RoleGuard>));

    expect(screen.getByText('Privileged admin content')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('completely hides the Configuration section, Design System, and Tokens badge from normal users and unauthenticated state', () => {
    const { rerender } = render(authenticated(normalUser, <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />));

    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin Control')).not.toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
    expect(screen.queryByText('Tokens')).not.toBeInTheDocument();
    expect(screen.getByText('Operations')).toBeInTheDocument();

    // Also hidden when user is null (loading / unauthenticated)
    rerender(
      <AuthContext.Provider value={{ user: null, logout: async () => undefined }}>
        <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />
      </AuthContext.Provider>,
    );
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
  });

  it('shows Configuration section, Admin Control, Settings, Design System, and Tokens to administrators and updates on role switch', () => {
    const { rerender } = render(authenticated(administrator, <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />));

    expect(screen.getByText('Configuration')).toBeInTheDocument();
    expect(screen.getByText('Admin Control')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
    expect(screen.getByText('Design System')).toBeInTheDocument();
    expect(screen.getByText('Tokens')).toBeInTheDocument();

    // Switching to normal user hides the entire Configuration section immediately
    rerender(authenticated(normalUser, <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />));
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin Control')).not.toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
    expect(screen.queryByText('Tokens')).not.toBeInTheDocument();
  });
});

describe('end-to-end role-based sidebar visibility and route guards', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
    Object.values(mockedApi).forEach((mock) => mock.mockReset());
    mockedApi.getApiHealth.mockResolvedValue({ status: 'healthy', application: 'VulnScanner API', version: '1.0.0' });
    mockedApi.endAuthSession.mockResolvedValue(undefined);
    mockedApi.logoutUser.mockResolvedValue(undefined);
  });

  it('hides Configuration on normal user login and refresh, and shows it on admin login and refresh', async () => {
    const browser = userEvent.setup({ delay: null });
    mockedApi.getAuthSession.mockRejectedValueOnce(Object.assign(new Error('Unauthorized'), { status: 401 }));
    mockedApi.loginUser.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: normalUser,
    });

    const firstRender = render(<App />);
    expect(screen.getByText('Checking secure session')).toBeInTheDocument();
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();

    await browser.type(await screen.findByLabelText('Username or email'), 'normal');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: 'Sign In' }));

    expect(await screen.findByText('Mock Security Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Operations')).toBeInTheDocument();
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
    expect(screen.queryByText('Tokens')).not.toBeInTheDocument();

    // Simulate normal user page refresh
    firstRender.unmount();
    mockedApi.getAuthSession.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: normalUser,
    });
    const secondRender = render(<App />);
    expect(await screen.findByText('Mock Security Dashboard')).toBeInTheDocument();
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
    expect(screen.queryByText('Tokens')).not.toBeInTheDocument();

    // Simulate admin page refresh
    secondRender.unmount();
    mockedApi.getAuthSession.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: administrator,
    });
    render(<App />);
    expect(await screen.findByText('Configuration')).toBeInTheDocument();
    expect(screen.getByText('Design System')).toBeInTheDocument();
    expect(screen.getByText('Tokens')).toBeInTheDocument();
  }, 15_000);

  it('removes Configuration when administrator logs out and a normal user logs in', async () => {
    const browser = userEvent.setup({ delay: null });
    mockedApi.getAuthSession.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: administrator,
    });
    mockedApi.loginUser.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: normalUser,
    });

    render(<App />);
    expect(await screen.findByText('Configuration')).toBeInTheDocument();
    expect(screen.getByText('Design System')).toBeInTheDocument();
    expect(screen.getByText('Tokens')).toBeInTheDocument();

    await browser.click(screen.getAllByRole('button', { name: 'Log out' })[0]);
    expect(await screen.findByText('Sign in to VulnScanner')).toBeInTheDocument();

    await browser.type(screen.getByLabelText('Username or email'), 'normal');
    await browser.type(screen.getByLabelText('Password'), 'StrongPassword!42');
    await browser.click(screen.getByRole('button', { name: 'Sign In' }));

    await waitFor(() => expect(screen.getByText('Operations')).toBeInTheDocument());
    expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
    expect(screen.queryByText('Design System')).not.toBeInTheDocument();
    expect(screen.queryByText('Tokens')).not.toBeInTheDocument();
  }, 15_000);

  it('denies manual navigation to /admin, /settings, and /design-system for normal users, while allowing Design System for admins', async () => {
    for (const restrictedPath of ['/admin', '/settings', '/design-system']) {
      window.history.replaceState({}, '', restrictedPath);
      mockedApi.getAuthSession.mockResolvedValueOnce({
        authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: normalUser,
      });

      const view = render(<App />);
      expect(await screen.findByRole('heading', { name: 'Access denied' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Administrator access required' })).toBeInTheDocument();
      expect(screen.queryByText('Mock Admin Control Page')).not.toBeInTheDocument();
      expect(screen.queryByText('Mock Settings Page')).not.toBeInTheDocument();
      expect(screen.queryByText('Configuration')).not.toBeInTheDocument();
      expect(screen.queryByText('Design System')).not.toBeInTheDocument();
      view.unmount();
    }

    // Admin can still access Design System and Tokens
    const browser = userEvent.setup({ delay: null });
    window.history.replaceState({}, '', '/');
    mockedApi.getAuthSession.mockResolvedValueOnce({
      authenticated: true, method: 'session', expires_at: '2026-12-01T00:00:00Z', user: administrator,
    });

    render(<App />);
    expect(await screen.findByText('Tokens')).toBeInTheDocument();
    await browser.click(screen.getByRole('button', { name: /Design System/i }));
    expect(await screen.findByRole('heading', { name: 'Design System Showcase' })).toBeInTheDocument();
  }, 15_000);
});
