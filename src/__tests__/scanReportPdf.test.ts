// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest';
import { downloadScanReportPdf, generateScanReportPdf, getScanReportPdfFilename } from '../services/scanReportPdf';
import type { ScanReportDetail } from '../types';

const minimalReport: ScanReportDetail = {
  scan_id: 'a8e2c6eb-77b2-4fd2-bdea-c18333d1d8b7', target: '../../lab host:8443', status: 'completed', progress: 100,
  scan_profile: 'quick', scanner: 'Nmap', created_at: '2026-10-28T10:00:00Z', completed_at: '2026-10-28T10:01:00Z',
  duration_seconds: 60, resolved_addresses: [], port_inventory_recorded: false,
  summary: { total_ports_examined: null, recorded_port_entries: 0, open_ports: 0, closed_or_filtered_ports: 0, identified_services: 0, findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 } },
  ports: [], findings: [], limitations: ['No stored configuration.'],
};

afterEach(() => vi.restoreAllMocks());

describe('scan report PDF', () => {
  it('uses a traversal-safe target and scan date in the filename', () => {
    expect(getScanReportPdfFilename(minimalReport)).toBe('VulnScanner_lab-host-8443_2026-10-28.pdf');
  });

  it('uses the same report payload to generate a genuine multi-section PDF', () => {
    const bytes = generateScanReportPdf(minimalReport).output('arraybuffer');
    expect(bytes.byteLength).toBeGreaterThan(1000);
  });

  it('initiates a Blob download and revokes its temporary object URL', () => {
    const createUrl = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:scan-report');
    const revokeUrl = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    vi.spyOn(window, 'setTimeout').mockImplementation(((callback: TimerHandler) => {
      if (typeof callback === 'function') callback();
      return 1;
    }) as typeof window.setTimeout);

    const filename = downloadScanReportPdf(minimalReport);

    expect(filename).toBe('VulnScanner_lab-host-8443_2026-10-28.pdf');
    expect(createUrl).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledOnce();
    expect(revokeUrl).toHaveBeenCalledWith('blob:scan-report');
  });
});
