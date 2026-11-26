import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { CreateScanInput, Scan } from '../types';
import { getScans, createScan, cancelScan, deleteScan as deleteScanApi } from '../services/api';
import { isActiveScanStatus } from '../utils/scanActivity';

interface ScanContextType {
  scans: Scan[];
  isLoading: boolean;
  isRefreshing: boolean;
  isStale: boolean;
  lastUpdated: number | null;
  error: string | null;
  addScan: (params: CreateScanInput) => Promise<Scan>;
  stopScan: (id: string) => Promise<Scan>;
  rerunScan: (id: string) => Promise<Scan | undefined>;
  deleteScan: (id: string) => Promise<void>;
  refreshScans: () => Promise<void>;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);
const DEFAULT_REFRESH_MS = 2500;

function refreshIntervalMs(): number {
  const configured = Number(import.meta.env.VITE_SCAN_REFRESH_INTERVAL_MS);
  return Number.isFinite(configured) && configured >= 1000 ? configured : DEFAULT_REFRESH_MS;
}

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isStale, setIsStale] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const requestRef = useRef<{ id: number; promise: Promise<void>; controller: AbortController } | null>(null);
  const requestIdRef = useRef(0);
  const mutationVersionRef = useRef(0);
  const scansRef = useRef(scans);

  useEffect(() => {
    scansRef.current = scans;
  }, [scans]);

  const refreshScans = useCallback(async (): Promise<void> => {
    // Sharing the in-flight promise prevents timer/manual refresh races.
    if (requestRef.current) return requestRef.current.promise;

    const controller = new AbortController();

    const requestId = ++requestIdRef.current;
    const requestMutationVersion = mutationVersionRef.current;
    const request = (async () => {
      if (mountedRef.current) setIsRefreshing(true);
      try {
        const data = await getScans(undefined, controller.signal);
        if (!mountedRef.current) return;
        if (mutationVersionRef.current === requestMutationVersion) {
          setScans(data);
          setError(null);
          setIsStale(false);
          setLastUpdated(Date.now());
        }
      } catch (err: unknown) {
        if (!mountedRef.current) return;
        const requestError = err instanceof Error ? err : new Error('Failed to fetch scans');
        setError(requestError.message);
        // Keep the last known good list; it is stale, not empty.
        setIsStale(scansRef.current.length > 0);
        throw requestError;
      } finally {
        if (mountedRef.current) {
          setIsLoading(false);
          setIsRefreshing(false);
        }
        if (requestRef.current?.id === requestId) {
          requestRef.current = null;
          if (mountedRef.current && mutationVersionRef.current !== requestMutationVersion) {
            void refreshScans().catch(() => {});
          }
        }
      }
    })();
    requestRef.current = { id: requestId, promise: request, controller };
    return request;
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void refreshScans().catch(() => {});
    return () => {
      mountedRef.current = false;
      const pending = requestRef.current;
      requestRef.current = null;
      pending?.controller.abort();
    };
  }, [refreshScans]);

  useEffect(() => {
    const poll = () => {
      if (document.visibilityState === 'visible' && scansRef.current.some((scan) => isActiveScanStatus(scan.status))) {
        void refreshScans().catch(() => {});
      }
    };
    const interval = window.setInterval(poll, refreshIntervalMs());
    document.addEventListener('visibilitychange', poll);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener('visibilitychange', poll);
    };
  }, [refreshScans]);

  useEffect(() => {
    const handleAuthenticationRequired = () => {
      setScans([]);
      setError('Authentication required. Scan state was cleared.');
      setIsStale(false);
      setLastUpdated(null);
    };
    window.addEventListener('vulnscanner:authentication-required', handleAuthenticationRequired);
    return () => window.removeEventListener('vulnscanner:authentication-required', handleAuthenticationRequired);
  }, []);

  const addScan = async (params: CreateScanInput) => {
    mutationVersionRef.current += 1;
    const newScan = await createScan(params);
    if (mountedRef.current) {
      setScans((previous) => [newScan, ...previous.filter((scan) => scan.id !== newScan.id)]);
    }
    return newScan;
  };

  const stopScan = async (id: string) => {
    mutationVersionRef.current += 1;
    const updated = await cancelScan(id);
    if (!updated) throw new Error(`Failed to cancel scan ${id}: backend returned no confirmation.`);
    setScans((previous) => previous.map((scan) => scan.id === id ? updated : scan));
    return updated;
  };

  const rerunScan = async (id: string) => {
    const existing = scans.find((scan) => scan.id === id);
    if (!existing) throw new Error(`Scan with ID '${id}' not found to re-run.`);
    return addScan({ name: existing.name, targetUrl: existing.targetUrl, type: existing.type });
  };

  const deleteScan = async (id: string) => {
    mutationVersionRef.current += 1;
    await deleteScanApi(id);
    setScans((previous) => previous.filter((scan) => scan.id !== id));
  };

  return (
    <ScanContext.Provider value={{ scans, isLoading, isRefreshing, isStale, lastUpdated, error, addScan, stopScan, rerunScan, deleteScan, refreshScans }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScans = () => {
  const context = useContext(ScanContext);
  if (!context) throw new Error('useScans must be used within a ScanProvider');
  return context;
};
