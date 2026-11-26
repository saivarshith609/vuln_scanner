// @vitest-environment jsdom

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { validateCidrTarget, validateIpRange, validateSingleTarget } from '../utils/targetValidator';
import type { DiscoveredHost, DiscoveryRun } from '../types';

const api = vi.hoisted(() => ({
  getDiscoveries: vi.fn(), getDiscovery: vi.fn(), getDiscoveryHosts: vi.fn(),
  createDiscovery: vi.fn(), cancelDiscovery: vi.fn(), createScan: vi.fn(),
}));
const toast = vi.hoisted(() => ({ showToast: vi.fn() }));

vi.mock('../services/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('../services/api')>()), ...api }));
vi.mock('../components/ui/Toast', async (importOriginal) => ({ ...(await importOriginal<typeof import('../components/ui/Toast')>()), useToast: () => toast }));

import { DiscoveryPage } from '../pages/DiscoveryPage';

const run: DiscoveryRun = {
  id: 'discovery-1', target: '192.168.50.0/24', target_kind: 'cidr', status: 'completed',
  authorization_mode: 'on_demand', authorization_confirmed: true,
  progress: 100, partial_results: false, created_at: '2026-10-28T12:00:00Z',
};
const host: DiscoveredHost = {
  id: 'host-1', discovery_id: run.id, ip_address: '192.168.50.7', hostname: 'printer.lab',
  mac_address: 'AA:BB:CC:DD:EE:FF', vendor: 'Example Devices', discovery_status: 'responding',
  last_seen_at: '2026-10-28T12:01:00Z', authorized: true,
};

beforeEach(() => {
  Object.values(api).forEach((mock) => mock.mockReset());
  toast.showToast.mockReset();
  api.getDiscoveries.mockResolvedValue([]);
  api.getDiscoveryHosts.mockResolvedValue([]);
});

describe('network target input validation', () => {
  it('keeps single hosts separate from CIDR discovery', () => {
    expect(validateSingleTarget('192.168.1.10')).toMatchObject({ isValid: true, addressCount: 1 });
    expect(validateSingleTarget('host.internal').isValid).toBe(true);
    expect(validateSingleTarget('192.168.1.0/24').error).toContain('CIDR subnet mode');
  });

  it('accepts bounded IPv4 and IPv6 CIDRs and rejects oversized scopes', () => {
    expect(validateCidrTarget('192.168.1.0/24', 4096)).toMatchObject({ isValid: true, addressCount: 256 });
    expect(validateCidrTarget('2001:db8::/120', 4096)).toMatchObject({ isValid: true, addressCount: 256 });
    expect(validateCidrTarget('10.0.0.0/8', 4096).error).toContain('safety limit');
  });

  it('validates range ordering, family, and size', () => {
    expect(validateIpRange('192.168.1.10', '192.168.1.20', 4096)).toMatchObject({ isValid: true, addressCount: 11 });
    expect(validateIpRange('192.168.1.20', '192.168.1.10').error).toContain('must not exceed');
    expect(validateIpRange('192.168.1.1', '2001:db8::1').error).toContain('same IP family');
    expect(validateIpRange('10.0.0.1', '10.0.20.1', 4096).error).toContain('safety limit');
  });
});

describe('network discovery UI', () => {
  it('launches CIDR discovery rather than a normal port scan', async () => {
    const user = userEvent.setup();
    api.createDiscovery.mockResolvedValue(run);
    api.getDiscovery.mockResolvedValue(run);
    render(<DiscoveryPage />);
    fireEvent.change(screen.getByLabelText('Authorized CIDR subnet'), {
      target: { value: '192.168.50.0/24' },
    });
    await user.click(screen.getByRole('checkbox', { name: /own this target/i }));
    await user.click(screen.getByRole('button', { name: 'Start Discovery' }));
    expect(api.createDiscovery).toHaveBeenCalledWith({ target_type: 'cidr', cidr: '192.168.50.0/24', authorization_mode: 'on_demand', authorization_confirmed: true });
    expect(api.createScan).not.toHaveBeenCalled();
  });

  it('shows persisted host metadata and scans a selected authorized IP through the normal scan API', async () => {
    const user = userEvent.setup();
    api.getDiscoveries.mockResolvedValue([run]);
    api.getDiscovery.mockResolvedValue(run);
    api.getDiscoveryHosts.mockResolvedValue([host]);
    api.createScan.mockResolvedValue({ id: 'scan-1' });
    render(<DiscoveryPage />);
    expect(await screen.findByText('printer.lab')).toBeInTheDocument();
    expect(screen.getByText('AA:BB:CC:DD:EE:FF')).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: `Select ${host.ip_address}` }));
    expect(screen.getByText('1 selected · 1 shown')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Scan Host' }));
    await waitFor(() => expect(api.createScan).toHaveBeenCalledWith({
      targetUrl: host.ip_address, type: 'quick', authorizationMode: 'on_demand', authorizationConfirmed: true,
    }));
  });

  it('does not claim an empty discovery means hosts are offline', async () => {
    api.getDiscoveries.mockResolvedValue([run]);
    api.getDiscovery.mockResolvedValue(run);
    api.getDiscoveryHosts.mockResolvedValue([]);
    render(<DiscoveryPage />);
    expect(await screen.findByText(/this is not proof that hosts are offline/i)).toBeInTheDocument();
  });
});
