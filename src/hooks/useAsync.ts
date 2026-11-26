import { useState, useEffect, useCallback } from 'react';

export type LoadingState = 'idle' | 'loading' | 'success' | 'error';

export interface UseAsyncResult<T> {
  data: T | null;
  state: LoadingState;
  error: string | null;
  refetch: () => void;
  isRefreshing: boolean;
  isStale: boolean;
  lastUpdated: number | null;
}

/**
 * Generic async data fetching hook with loading/error/success states.
 * Automatically re-fetches when deps change.
 */
export function useAsync<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  deps: unknown[] = []
): UseAsyncResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [state, setState] = useState<LoadingState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [trigger, setTrigger] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isStale, setIsStale] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  const refetch = useCallback(() => setTrigger((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    if (data === null) setState('loading');
    setIsRefreshing(true);
    setError(null);

    fn(controller.signal)
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setState('success');
          setIsStale(false);
          setLastUpdated(Date.now());
          setIsRefreshing(false);
        }
      })
      .catch((err: Error) => {
        if (!cancelled && err?.name !== 'AbortError') {
          setError(err?.message || 'An unexpected error occurred.');
          setState(data === null ? 'error' : 'success');
          setIsStale(data !== null);
          setIsRefreshing(false);
        }
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, trigger]);

  return { data, state, error, refetch, isRefreshing, isStale, lastUpdated };
}
