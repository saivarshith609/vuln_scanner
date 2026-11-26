// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthContext } from '../components/auth/authContext';
import { RoleGuard } from '../components/auth/RoleGuard';
import { Sidebar } from '../layouts/Sidebar';
import type { AuthUser } from '../services/api';

vi.mock('../store/ScanContext', () => ({
  useScans: () => ({
    scans: [], isLoading: false, isRefreshing: false, isStale: false, error: null,
  }),
}));

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
