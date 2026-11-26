import type { Scan, ScanStatus } from '../types';

export const ACTIVE_SCAN_STATUSES: readonly ScanStatus[] = ['queued', 'running'];

export function isActiveScanStatus(status: ScanStatus): boolean {
  return status === 'queued' || status === 'running';
}

export function getActiveScanCount(scans: readonly Scan[]): number {
  return scans.reduce(
    (count, scan) => count + (isActiveScanStatus(scan.status) ? 1 : 0),
    0,
  );
}
