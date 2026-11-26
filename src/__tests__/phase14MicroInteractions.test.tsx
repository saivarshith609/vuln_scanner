/// <reference types="node" />
// @vitest-environment jsdom

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LiveScansWidget } from '../components/dashboard/LiveScansWidget';
import { RadarPing } from '../components/ui/RadarPing';
import type { Scan, ScanStatus } from '../types';
import { getActiveScanCount, isActiveScanStatus } from '../utils/scanActivity';

const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

function scan(id: string, status: ScanStatus): Scan {
  return {
    id,
    name: `Backend scan ${id}`,
    targetUrl: 'scanner.internal',
    type: 'quick',
    status,
    progress: status === 'completed' ? 100 : 25,
    startedAt: '2026-10-28T08:00:00Z',
    findings,
  };
}

function renderWidget(activeScanCount: number, activityIsStale = false) {
  return render(
    <LiveScansWidget
      scans={[]}
      activeScanCount={activeScanCount}
      activityIsStale={activityIsStale}
      onViewAllScans={vi.fn()}
    />,
  );
}

describe('Phase 14 scan-driven radar and micro-interactions', () => {
  it('treats only queued and running backend scan states as active', () => {
    const statuses: ScanStatus[] = ['idle', 'queued', 'running', 'completed', 'failed', 'paused', 'cancelled'];

    expect(statuses.filter(isActiveScanStatus)).toEqual(['queued', 'running']);
    expect(getActiveScanCount(statuses.map((status, index) => scan(String(index), status)))).toBe(2);
  });

  it.each<ScanStatus>(['completed', 'failed', 'cancelled'])('stops the radar for the %s terminal state', (status) => {
    expect(getActiveScanCount([scan('terminal', status)])).toBe(0);
    const { container } = renderWidget(0);
    expect(screen.getByText('Idle')).toBeInTheDocument();
    expect(container.querySelector('.vs-radar-ping')).toHaveAttribute('data-active', 'false');
  });

  it('shows the dashboard radar only when genuine shared scan state is active', () => {
    const activeScans = [scan('queued', 'queued'), scan('running', 'running')];
    const activeCount = getActiveScanCount(activeScans);
    const { container } = renderWidget(activeCount);

    expect(screen.getByText('2 active')).toBeInTheDocument();
    expect(container.querySelector('.vs-radar-ping')).toHaveAttribute('data-active', 'true');
    expect(container.querySelector('.vs-radar-ping')).toHaveClass('vs-radar-ping--active');
  });

  it('renders an idle radar without an animation-triggering active class', () => {
    const { container } = render(<RadarPing active={false} />);
    const radar = container.querySelector('.vs-radar-ping');

    expect(radar).toHaveAttribute('data-active', 'false');
    expect(radar).not.toHaveClass('vs-radar-ping--active');
  });

  it('does not animate last-known activity after scan telemetry becomes stale', () => {
    const { container } = renderWidget(1, true);
    expect(screen.getByText('Stale')).toBeInTheDocument();
    expect(container.querySelector('.vs-radar-ping')).toHaveAttribute('data-active', 'false');
  });

  it('provides reduced-motion overrides for both radar and existing application animations', () => {
    const radarCss = readFileSync(resolve('src/components/ui/RadarPing.css'), 'utf8');
    const globalCss = readFileSync(resolve('src/index.css'), 'utf8');

    expect(radarCss).toContain('@media (prefers-reduced-motion: reduce)');
    expect(radarCss).toContain('animation: none');
    expect(globalCss).toContain('@media (prefers-reduced-motion: reduce)');
    expect(globalCss).toContain('animation-iteration-count: 1 !important');
  });

  it('does not retain hard-coded production scan or vulnerability activity badges', () => {
    const sidebarSource = readFileSync(resolve('src/layouts/Sidebar.tsx'), 'utf8');

    expect(sidebarSource).not.toContain("badge: '2 active'");
    expect(sidebarSource).not.toContain("badge: '14 crit'");
    expect(sidebarSource).not.toContain('Workers Active');
    expect(sidebarSource).toContain('getActiveScanCount(scans)');
  });
});
