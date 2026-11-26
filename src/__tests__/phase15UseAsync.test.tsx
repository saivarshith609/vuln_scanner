// @vitest-environment jsdom

import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useAsync } from '../hooks/useAsync';

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('Phase 15 useAsync lifecycle', () => {
  it('exposes loading and then the successful backend result', async () => {
    const request = deferred<{ count: number }>();
    const loader = vi.fn(() => request.promise);
    const { result } = renderHook(() => useAsync(loader));

    expect(result.current.state).toBe('loading');
    expect(result.current.isRefreshing).toBe(true);
    expect(result.current.data).toBeNull();

    await act(async () => request.resolve({ count: 4 }));

    await waitFor(() => expect(result.current.state).toBe('success'));
    expect(result.current.data).toEqual({ count: 4 });
    expect(result.current.error).toBeNull();
    expect(result.current.lastUpdated).not.toBeNull();
  });

  it('keeps last-known-good data and marks it stale after refresh failure', async () => {
    const loader = vi.fn<() => Promise<string>>()
      .mockResolvedValueOnce('confirmed telemetry')
      .mockRejectedValueOnce(new Error('refresh unavailable'));
    const { result } = renderHook(() => useAsync(loader));

    await waitFor(() => expect(result.current.data).toBe('confirmed telemetry'));
    const successfulUpdate = result.current.lastUpdated;

    act(() => result.current.refetch());
    await waitFor(() => expect(result.current.isStale).toBe(true));

    expect(result.current.state).toBe('success');
    expect(result.current.data).toBe('confirmed telemetry');
    expect(result.current.error).toBe('refresh unavailable');
    expect(result.current.isRefreshing).toBe(false);
    expect(result.current.lastUpdated).toBe(successfulUpdate);
  });

  it('exposes a truthful initial error when no successful data exists', async () => {
    const loader = vi.fn().mockRejectedValueOnce(undefined);
    const { result } = renderHook(() => useAsync(loader));

    await waitFor(() => expect(result.current.state).toBe('error'));
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBe('An unexpected error occurred.');
    expect(result.current.isStale).toBe(false);
  });

  it('aborts superseded requests and prevents stale responses overwriting newer data', async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const signals: AbortSignal[] = [];
    const loader = vi.fn((dependency: number, signal?: AbortSignal) => {
      if (signal) signals.push(signal);
      return dependency === 1 ? first.promise : second.promise;
    });

    const { result, rerender } = renderHook(
      ({ dependency }) => useAsync((signal) => loader(dependency, signal), [dependency]),
      { initialProps: { dependency: 1 } },
    );

    rerender({ dependency: 2 });
    expect(signals[0].aborted).toBe(true);

    await act(async () => second.resolve('new response'));
    await waitFor(() => expect(result.current.data).toBe('new response'));

    await act(async () => first.resolve('stale response'));
    expect(result.current.data).toBe('new response');
  });

  it('aborts an in-flight request on unmount without leaking a rejection', async () => {
    let requestSignal: AbortSignal | undefined;
    const loader = vi.fn((signal?: AbortSignal) => {
      requestSignal = signal;
      return new Promise<string>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      });
    });
    const { unmount } = renderHook(() => useAsync(loader));

    unmount();
    await Promise.resolve();

    expect(requestSignal?.aborted).toBe(true);
  });
});
