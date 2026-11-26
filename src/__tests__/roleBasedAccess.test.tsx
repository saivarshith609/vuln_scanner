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

  it('hides administrator navigation and settings from normal users', () => {
    render(authenticated(normalUser, <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />));

    expect(screen.queryByText('Admin Control')).not.toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });

  it('shows administrator navigation to administrators', () => {
    render(authenticated(administrator, <Sidebar currentTab="dashboard" onSelectTab={vi.fn()} isCollapsed={false} onToggleCollapse={vi.fn()} />));

    expect(screen.getByText('Admin Control')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });
});
