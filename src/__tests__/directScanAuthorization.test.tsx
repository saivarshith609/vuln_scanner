// @vitest-environment jsdom

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Scan } from '../types';

const mocks = vi.hoisted(() => ({
  addScan: vi.fn(),
  createDiscovery: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock('../store/ScanContext', () => ({
  useScans: () => ({ addScan: mocks.addScan }),
}));
vi.mock('../components/ui/Toast', () => ({
  useToast: () => ({ showToast: mocks.showToast }),
}));
vi.mock('../services/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../services/api')>()),
  createDiscovery: mocks.createDiscovery,
}));
vi.mock('../layouts/Sidebar', () => ({ Sidebar: () => null }));
vi.mock('../layouts/Header', () => ({ Header: () => null }));

import { AppShell } from '../layouts/AppShell';

const queuedScan: Scan = {
  id: 'direct-scan',
  name: '192.168.29.31 Audit',
  targetUrl: '192.168.29.31',
  type: 'quick',
  status: 'queued',
  progress: 0,
  startedAt: '2026-10-28T12:00:00Z',
  findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
};

describe('Direct scan authorization workflow', () => {
  beforeEach(() => {
    mocks.addScan.mockReset().mockResolvedValue(queuedScan);
    mocks.createDiscovery.mockReset();
    mocks.showToast.mockReset();
  });

  it('requires explicit permission confirmation and submits an on-demand target', async () => {
    const user = userEvent.setup();
    render(
      <AppShell
        currentTab="scans"
        onSelectTab={vi.fn()}
        title="Scans"
        isNewScanOpen
        onCloseNewScan={vi.fn()}
      >
        <div />
      </AppShell>,
    );

    const runButton = screen.getByRole('button', { name: /initialize & run/i });
    expect(runButton).toBeDisabled();

    await user.type(screen.getByLabelText('Target IP Address or Hostname'), '192.168.29.31');
    expect(runButton).toBeDisabled();

    await user.click(screen.getByRole('checkbox', { name: /own this target or have explicit permission/i }));
    expect(runButton).toBeEnabled();
    await user.click(runButton);

    expect(mocks.addScan).toHaveBeenCalledWith({
      name: '192.168.29.31 Audit',
      targetUrl: '192.168.29.31',
      type: 'quick',
      authorizationMode: 'on_demand',
      authorizationConfirmed: true,
    });
  });

  it('requires confirmation again after the target changes', async () => {
    const user = userEvent.setup();
    render(
      <AppShell currentTab="scans" onSelectTab={vi.fn()} title="Scans" isNewScanOpen>
        <div />
      </AppShell>,
    );

    const target = screen.getByLabelText('Target IP Address or Hostname');
    const confirmation = screen.getByRole('checkbox', { name: /own this target or have explicit permission/i });
    const runButton = screen.getByRole('button', { name: /initialize & run/i });

    await user.type(target, '192.168.29.31');
    await user.click(confirmation);
    expect(runButton).toBeEnabled();
    await user.type(target, '2');

    expect(confirmation).not.toBeChecked();
    expect(runButton).toBeDisabled();
  });

  it('routes an authorized CIDR through host discovery, not the single-host scan API', async () => {
    const user = userEvent.setup();
    mocks.createDiscovery.mockResolvedValue({ id: 'discovery-1', target: '192.168.29.0/24' });
    const selectTab = vi.fn();
    render(
      <AppShell currentTab="scans" onSelectTab={selectTab} title="Scans" isNewScanOpen>
        <div />
      </AppShell>,
    );

    await user.click(screen.getByRole('button', { name: 'CIDR Subnet' }));
    expect(screen.getByRole('button', { name: /network discovery/i })).toHaveAttribute('aria-pressed', 'true');
    await user.type(screen.getByLabelText('Authorized CIDR Subnet'), '192.168.29.0/24');
    await user.click(screen.getByRole('checkbox', { name: /own this target or have explicit permission/i }));
    await user.click(screen.getByRole('button', { name: /initialize & run/i }));

    expect(mocks.createDiscovery).toHaveBeenCalledWith({
      target_type: 'cidr', cidr: '192.168.29.0/24', authorization_mode: 'on_demand', authorization_confirmed: true,
    });
    expect(mocks.addScan).not.toHaveBeenCalled();
    expect(selectTab).toHaveBeenCalledWith('discovery');
  });

  it('supports an authorized IP range through the discovery endpoint', async () => {
    const user = userEvent.setup();
    mocks.createDiscovery.mockResolvedValue({ id: 'discovery-2', target: '192.168.29.10-192.168.29.20' });
    render(
      <AppShell currentTab="scans" onSelectTab={vi.fn()} title="Scans" isNewScanOpen>
        <div />
      </AppShell>,
    );

    await user.click(screen.getByRole('button', { name: 'IP Range' }));
    await user.type(screen.getByLabelText('Range Start IP'), '192.168.29.10');
    await user.type(screen.getByLabelText('Range End IP'), '192.168.29.20');
    await user.click(screen.getByRole('checkbox', { name: /own this target or have explicit permission/i }));
    await user.click(screen.getByRole('button', { name: /initialize & run/i }));

    expect(mocks.createDiscovery).toHaveBeenCalledWith({
      target_type: 'range', start_ip: '192.168.29.10', end_ip: '192.168.29.20', authorization_mode: 'on_demand', authorization_confirmed: true,
    });
    expect(mocks.addScan).not.toHaveBeenCalled();
  });

  it('shows invalid CIDR and backend discovery failures in the target field', async () => {
    const user = userEvent.setup();
    render(
      <AppShell currentTab="scans" onSelectTab={vi.fn()} title="Scans" isNewScanOpen>
        <div />
      </AppShell>,
    );
    await user.click(screen.getByRole('button', { name: 'CIDR Subnet' }));
    const target = screen.getByLabelText('Authorized CIDR Subnet');
    const confirm = screen.getByRole('checkbox', { name: /own this target or have explicit permission/i });
    await user.type(target, '192.168.29.0/99');
    await user.click(confirm);
    await user.click(screen.getByRole('button', { name: /initialize & run/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/valid IPv4 or IPv6 CIDR/i);
    expect(mocks.createDiscovery).not.toHaveBeenCalled();

    await user.clear(target);
    await user.type(target, '192.168.29.0/24');
    await user.click(confirm);
    mocks.createDiscovery.mockRejectedValueOnce(new Error('Authorization confirmation could not be verified.'));
    await user.click(screen.getByRole('button', { name: /initialize & run/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/authorization confirmation could not be verified/i);
  });
});
