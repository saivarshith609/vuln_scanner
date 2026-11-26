// @vitest-environment jsdom

import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Scan, ScanStatus } from '../types';

const api = vi.hoisted(() => ({
  getScans: vi.fn(),
  createScan: vi.fn(),
  cancelScan: vi.fn(),
  deleteScan: vi.fn(),
}));

vi.mock('../services/api', () => ({
  getScans: api.getScans,
  createScan: api.createScan,
  cancelScan: api.cancelScan,
  deleteScan: api.deleteScan,
}));

import { ScanProvider, useScans } from '../store/ScanContext';

const findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

function scan(id: string, status: ScanStatus = 'completed'): Scan {
  return {
    id,
    name: `Scan ${id}`,
    targetUrl: `${id}.internal`,
    type: 'quick',
    status,
    progress: status === 'completed' ? 100 : 20,
    startedAt: '2026-10-28T08:00:00Z',
    findings,
  };
}

const wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <ScanProvider>{children}</ScanProvider>
);

describe('Phase 15 shared ScanContext integration', () => {
  beforeEach(() => {
    api.getScans.mockReset().mockResolvedValue([]);
    api.createScan.mockReset();
    api.cancelScan.mockReset();
    api.deleteScan.mockReset().mockResolvedValue({ success: true });
  });

  it('loads, creates, cancels, reruns, and deletes backend-confirmed scans', async () => {
    const original = scan('original');
    const created = scan('created', 'queued');
    const cancelled = scan('created', 'cancelled');
    const rerun = scan('rerun', 'queued');
    api.getScans.mockResolvedValueOnce([original]);
    api.createScan.mockResolvedValueOnce(created).mockResolvedValueOnce(rerun);
    api.cancelScan.mockResolvedValueOnce(cancelled);

    const { result } = renderHook(() => useScans(), { wrapper });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.scans).toEqual([original]);

    await act(async () => {
      await result.current.addScan({ name: created.name, targetUrl: created.targetUrl, type: created.type });
    });
    expect(result.current.scans.map((item) => item.id)).toEqual(['created', 'original']);

    await act(async () => {
      await result.current.stopScan(created.id);
    });
    expect(result.current.scans.find((item) => item.id === created.id)?.status).toBe('cancelled');

    await act(async () => {
      await result.current.rerunScan(original.id);
    });
    expect(api.createScan).toHaveBeenLastCalledWith({
      name: original.name,
      targetUrl: original.targetUrl,
      type: original.type,
    });
    expect(result.current.scans[0].id).toBe('rerun');

    await act(async () => {
      await result.current.deleteScan(original.id);
    });
    expect(api.deleteScan).toHaveBeenCalledWith(original.id);
    expect(result.current.scans.some((item) => item.id === original.id)).toBe(false);
  });

  it('retains last-known scans on refresh failure and recovers on retry', async () => {
    const confirmed = scan('confirmed');
    const refreshed = scan('refreshed');
    api.getScans.mockResolvedValueOnce([confirmed]);
    const { result } = renderHook(() => useScans(), { wrapper });
    await waitFor(() => expect(result.current.scans).toEqual([confirmed]));

    api.getScans.mockRejectedValueOnce(new Error('scanner API unavailable'));
    await act(async () => {
      await result.current.refreshScans().catch(() => undefined);
    });

    expect(result.current.scans).toEqual([confirmed]);
    expect(result.current.isStale).toBe(true);
    expect(result.current.error).toBe('scanner API unavailable');

    api.getScans.mockResolvedValueOnce([refreshed]);
    await act(async () => result.current.refreshScans());
    expect(result.current.scans).toEqual([refreshed]);
    expect(result.current.isStale).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('does not let a pre-mutation refresh overwrite a newly created scan', async () => {
    let resolveInitial!: (value: Scan[]) => void;
    const created = scan('newly-created', 'queued');
    api.getScans
      .mockReturnValueOnce(new Promise<Scan[]>((resolve) => {
        resolveInitial = resolve;
      }))
      .mockResolvedValueOnce([created]);
    api.createScan.mockResolvedValueOnce(created);
    const { result } = renderHook(() => useScans(), { wrapper });

    await act(async () => {
      await result.current.addScan({ name: created.name, targetUrl: created.targetUrl, type: created.type });
    });
    expect(result.current.scans).toEqual([created]);

    await act(async () => resolveInitial([scan('stale-server-response')]));
    await waitFor(() => expect(api.getScans).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(result.current.scans).toEqual([created]));
    expect(result.current.scans.some((item) => item.id === 'stale-server-response')).toBe(false);
  });

  it('clears protected scan state when authentication expires', async () => {
    api.getScans.mockResolvedValueOnce([scan('protected', 'running')]);
    const { result } = renderHook(() => useScans(), { wrapper });
    await waitFor(() => expect(result.current.scans).toHaveLength(1));

    act(() => window.dispatchEvent(new Event('vulnscanner:authentication-required')));

    expect(result.current.scans).toEqual([]);
    expect(result.current.error).toContain('Authentication required');
    expect(result.current.isStale).toBe(false);
  });

  it('polls only while a fresh scan is active and stops after terminal state', async () => {
    vi.useFakeTimers();
    api.getScans
      .mockResolvedValueOnce([scan('polling', 'running')])
      .mockResolvedValueOnce([scan('polling', 'completed')]);
    const { result } = renderHook(() => useScans(), { wrapper });

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(result.current.scans[0]?.status).toBe('running');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2500);
    });
    expect(api.getScans).toHaveBeenCalledTimes(2);
    expect(result.current.scans[0]?.status).toBe('completed');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(api.getScans).toHaveBeenCalledTimes(2);
  });

  it('does not overlap active-scan polling requests', async () => {
    vi.useFakeTimers();
    let resolvePoll!: (value: Scan[]) => void;
    api.getScans
      .mockResolvedValueOnce([scan('slow-poll', 'running')])
      .mockReturnValueOnce(new Promise<Scan[]>((resolve) => {
        resolvePoll = resolve;
      }));
    renderHook(() => useScans(), { wrapper });

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    await act(async () => vi.advanceTimersByTimeAsync(2500));
    expect(api.getScans).toHaveBeenCalledTimes(2);

    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(api.getScans).toHaveBeenCalledTimes(2);

    await act(async () => resolvePoll([scan('slow-poll', 'completed')]));
  });

  it('aborts an initial refresh when the provider unmounts', async () => {
    let capturedSignal: AbortSignal | undefined;
    api.getScans.mockImplementationOnce((_params: unknown, signal?: AbortSignal) => {
      capturedSignal = signal;
      return new Promise<Scan[]>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      });
    });

    const { unmount } = renderHook(() => useScans(), { wrapper });
    unmount();
    await Promise.resolve();

    expect(capturedSignal?.aborted).toBe(true);
  });
});
