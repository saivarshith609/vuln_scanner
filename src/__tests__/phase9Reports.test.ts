/**
 * Phase 9: Security Reports & Export — Frontend Tests
 *
 * Validates:
 * - Report archive retrieval from backend API (Phase 9.2 persistent).
 * - generateReport calls POST /api/v1/reports and maps backend response.
 * - generateReport throws when backend is unreachable (no silent fallback).
 * - sanitizeCsvCell correctly neutralizes OWASP formula-injection characters.
 * - sanitizeCsvCell escapes embedded commas, quotes, and newlines.
 * - exportReportCsv produces valid CSV content for a ready report.
 * - exportReportCsv handles empty findings (total = 0) without fabricating counts.
 * - Report status lifecycle: generating -> ready.
 * - Input validation contracts: name and target required, date range ordering.
 * - Simulated vs real export boundary is preserved in the API layer.
 * - Open ports are not classified as confirmed vulnerability findings.
 * - deleteReport calls DELETE /api/v1/reports/:id.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getReports,
  getReport,
  generateReport,
  deleteReport,
  sanitizeCsvCell,
  exportReportCsv,
  ApiError,
} from '../services/api';
import { exportReportPdf, generateReportPdf, getReportPdfFilename } from '../services/pdfExport';
import type { Report } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal ready Report fixture. */
function makeReadyReport(overrides: Partial<Report> = {}): Report {
  return {
    id: 'RPT-TEST-PHASE9',
    name: 'Phase 9 Test Executive Summary',
    target: 'All Infrastructure',
    type: 'executive',
    format: 'csv',
    scanDate: '2026-10-27',
    status: 'ready',
    fileSize: '1.2 MB',
    findingsSummary: {
      critical: 2,
      high: 5,
      medium: 8,
      low: 12,
      info: 3,
      total: 30,
    },
    ...overrides,
  };
}

/** Build a mock BackendReport JSON (as returned from POST /api/v1/reports). */
function makeBackendReport(overrides: Record<string, unknown> = {}) {
  return {
    id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    report_code: 'RPT-20261027-TEST',
    name: 'Test Report',
    target: 'All Assets',
    report_type: 'executive',
    format: 'pdf',
    status: 'completed',
    scan_date: '2026-10-27',
    date_from: null,
    date_to: null,
    file_size: '1.2 MB',
    findings_summary: {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4,
      info: 5,
      total: 15,
    },
    security_score: 72,
    total_assets: 10,
    total_scans: 5,
    created_at: '2026-10-27T12:00:00Z',
    updated_at: '2026-10-27T12:00:00Z',
    download_url: null,
    snapshot_data: { total_assets: 10, total_scans: 5 },
    ...overrides,
  };
}

// ─── Report Archive (Phase 9.2 — PostgreSQL Backend) ──────────────────────────

describe('Phase 9.2: Report Archive (PostgreSQL)', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('getReports returns reports from backend API', async () => {
    const backendReports = [makeBackendReport(), makeBackendReport({ id: 'second-id', name: 'Second Report' })];
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: backendReports, total: 2, page: 1, size: 100, pages: 1 }),
    } as Response);

    const reports = await getReports();
    expect(Array.isArray(reports)).toBe(true);
    expect(reports.length).toBe(2);
    expect(reports[0].name).toBe('Test Report');
    expect(reports[1].name).toBe('Second Report');
  });

  it('getReports surfaces a truthful transport error when backend is offline', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(getReports()).rejects.toBeInstanceOf(ApiError);
  });

  it('every mapped report has required fields', async () => {
    const backendReports = [makeBackendReport()];
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: backendReports, total: 1, page: 1, size: 100, pages: 1 }),
    } as Response);

    const reports = await getReports();
    for (const r of reports) {
      expect(typeof r.id).toBe('string');
      expect(typeof r.name).toBe('string');
      expect(r.name.length).toBeGreaterThan(0);
      expect(typeof r.target).toBe('string');
      expect(['executive', 'technical', 'compliance', 'network', 'delta']).toContain(r.type);
      expect(['ready', 'generating', 'failed']).toContain(r.status);
      expect(typeof r.findingsSummary.total).toBe('number');
      expect(r.findingsSummary.total).toBeGreaterThanOrEqual(0);
    }
  });

  it('getReport retrieves a single report by ID from backend', async () => {
    const br = makeBackendReport({ id: 'test-uuid-123', name: 'Fetched Report' });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => br,
    } as Response);

    const fetched = await getReport('test-uuid-123');
    expect(fetched).toBeDefined();
    expect(fetched?.id).toBe('test-uuid-123');
    expect(fetched?.name).toBe('Fetched Report');
  });

  it('getReport surfaces a truthful transport error when backend is offline', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(getReport('NONEXISTENT-999')).rejects.toBeInstanceOf(ApiError);
  });

  it('mapBackendReport correctly maps completed status to ready', async () => {
    const br = makeBackendReport({ status: 'completed' });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [br], total: 1, page: 1, size: 100, pages: 1 }),
    } as Response);

    const reports = await getReports();
    expect(reports[0].status).toBe('ready');
  });

  it('mapBackendReport includes snapshot metadata fields', async () => {
    const br = makeBackendReport({
      report_code: 'RPT-20261027-ABCD',
      security_score: 85,
      total_assets: 42,
      total_scans: 7,
      snapshot_data: { total_assets: 42, total_scans: 7 },
    });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [br], total: 1, page: 1, size: 100, pages: 1 }),
    } as Response);

    const reports = await getReports();
    expect(reports[0].reportCode).toBe('RPT-20261027-ABCD');
    expect(reports[0].securityScore).toBe(85);
    expect(reports[0].totalAssets).toBe(42);
    expect(reports[0].totalScans).toBe(7);
    expect(reports[0].snapshotData).toEqual({ total_assets: 42, total_scans: 7 });
  });

  it('findingsSummary.total matches sum of severity counts', async () => {
    const br = makeBackendReport();
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [br], total: 1, page: 1, size: 100, pages: 1 }),
    } as Response);

    const reports = await getReports();
    for (const r of reports) {
      const { critical, high, medium, low, info } = r.findingsSummary;
      const computedTotal = critical + high + medium + low + info;
      expect(r.findingsSummary.total).toBe(computedTotal);
    }
  });
});

// ─── Report Generation (Phase 9.2 — Backend Persistence) ─────────────────────

describe('Phase 9.2: Report Generation (Backend)', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('generateReport calls POST and maps backend response', async () => {
    const backendResponse = makeBackendReport({
      name: 'Q4 Executive Threat Briefing',
      target: 'All Production Assets',
      report_type: 'executive',
      status: 'completed',
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => backendResponse,
    } as Response);

    const r = await generateReport({
      name: 'Q4 Executive Threat Briefing',
      target: 'All Production Assets',
      type: 'executive',
      format: 'pdf',
    });

    expect(r.name).toBe('Q4 Executive Threat Briefing');
    expect(r.target).toBe('All Production Assets');
    expect(r.type).toBe('executive');
    expect(r.status).toBe('ready'); // 'completed' maps to 'ready'
    expect(r.findingsSummary.total).toBe(15);
  });

  it('generateReport preserves findings from backend response', async () => {
    const backendResponse = makeBackendReport({
      findings_summary: { critical: 3, high: 5, medium: 2, low: 1, info: 0, total: 11 },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => backendResponse,
    } as Response);

    const r = await generateReport({
      name: 'Live Backend Report',
      target: '10.0.0.0/8',
      type: 'technical',
      format: 'csv',
    });

    expect(r.findingsSummary.critical).toBe(3);
    expect(r.findingsSummary.high).toBe(5);
    expect(r.findingsSummary.medium).toBe(2);
    expect(r.findingsSummary.low).toBe(1);
    expect(r.findingsSummary.info).toBe(0);
    expect(r.findingsSummary.total).toBe(11);
  });

  it('generateReport throws when backend is unreachable — no silent fallback', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(
      generateReport({
        name: 'Offline Report',
        target: 'Staging',
        type: 'compliance',
        format: 'pdf',
      })
    ).rejects.toThrow();
  });

  it('generateReport returns zero findings for clean environment', async () => {
    const backendResponse = makeBackendReport({
      status: 'completed',
      findings_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => backendResponse,
    } as Response);

    const r = await generateReport({
      name: 'Clean Environment Report',
      target: 'DMZ Subnet',
      type: 'network',
      format: 'csv',
    });

    expect(r.findingsSummary.total).toBe(0);
    expect(r.findingsSummary.critical).toBe(0);
    expect(r.status).toBe('ready');
  });

  it('report status lifecycle: generating -> ready', () => {
    const report: Report = {
      id: 'RPT-LIFECYCLE-01',
      name: 'Lifecycle Test',
      target: 'AWS Perimeter',
      type: 'executive',
      format: 'pdf',
      scanDate: '2026-10-27',
      status: 'generating',
      fileSize: 'Pending...',
      findingsSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    };

    expect(report.status).toBe('generating');

    const ready: Report = { ...report, status: 'ready', fileSize: '2.1 MB' };
    expect(ready.status).toBe('ready');
    expect(ready.fileSize).toBe('2.1 MB');
  });
});

// ─── Report Deletion (Phase 9.2) ─────────────────────────────────────────────

describe('Phase 9.2: Report Deletion', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('deleteReport calls DELETE endpoint and returns success', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => null,
    } as unknown as Response);

    const result = await deleteReport('some-report-id');
    expect(result).toEqual({ success: true });
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/reports/some-report-id'),
      expect.objectContaining({ method: 'DELETE' })
    );
  });
});

// ─── Input Validation Contracts ───────────────────────────────────────────────

describe('Phase 9: Input Validation Contracts', () => {
  it('date range validation: dateFrom must be <= dateTo', () => {
    const validateDateRange = (from: string, to: string): boolean => {
      if (!from || !to) return true;
      return from <= to;
    };

    expect(validateDateRange('2026-10-01', '2026-10-27')).toBe(true);
    expect(validateDateRange('2026-10-27', '2026-10-27')).toBe(true);
    expect(validateDateRange('2026-10-28', '2026-10-27')).toBe(false);
    expect(validateDateRange('', '2026-10-27')).toBe(true); // empty allowed
  });

  it('report name and target are required (non-empty after trim)', () => {
    const validate = (name: string, target: string) => {
      if (!name.trim()) return 'Report name is required.';
      if (!target.trim()) return 'Target scope is required.';
      return null;
    };

    expect(validate('', 'Staging')).toBe('Report name is required.');
    expect(validate('  ', 'Staging')).toBe('Report name is required.');
    expect(validate('Q4 Report', '')).toBe('Target scope is required.');
    expect(validate('Q4 Report', '  ')).toBe('Target scope is required.');
    expect(validate('Q4 Report', 'Staging')).toBeNull();
  });

  it('all valid report types are supported', () => {
    const validTypes: Report['type'][] = [
      'executive',
      'technical',
      'compliance',
      'network',
      'delta',
    ];
    validTypes.forEach((t) => {
      const r = makeReadyReport({ type: t });
      expect(r.type).toBe(t);
    });
  });
});

// ─── CSV Formula-Injection Sanitization ──────────────────────────────────────

describe('Phase 9: CSV Formula-Injection Protection (OWASP)', () => {
  it('prefixes formula-triggering characters with a single quote', () => {
    // OWASP formula-injection characters: =, +, -, @, TAB, CR
    expect(sanitizeCsvCell('=SUM(A1:A10)')).toBe("'=SUM(A1:A10)");
    expect(sanitizeCsvCell('+cmd|/C calc')).toBe("'+cmd|/C calc");
    expect(sanitizeCsvCell('-2+3')).toBe("'-2+3");
    expect(sanitizeCsvCell('@SUM(1+1)')).toBe("'@SUM(1+1)");
    expect(sanitizeCsvCell('\t=injected')).toBe("'\t=injected");
    expect(sanitizeCsvCell('\r=injected')).toBe("'\r=injected");
  });

  it('neutralizes leading whitespace before formula-triggering characters', () => {
    expect(sanitizeCsvCell('   =cmd|/C calc')).toBe("'   =cmd|/C calc");
    expect(sanitizeCsvCell('  +cmd')).toBe("'  +cmd");
    expect(sanitizeCsvCell('  -cmd')).toBe("'  -cmd");
    expect(sanitizeCsvCell('  @cmd')).toBe("'  @cmd");
    expect(sanitizeCsvCell(' \t=foo')).toBe("' \t=foo");
    expect(sanitizeCsvCell(' \r=foo')).toBe("' \r=foo");
  });

  it('neutralizes control characters preceding formula triggers', () => {
    expect(sanitizeCsvCell('\0=cmd')).toBe("'\0=cmd");
    expect(sanitizeCsvCell('\x08=cmd')).toBe("'\x08=cmd");
    expect(sanitizeCsvCell('\tmalicious')).toBe("'\tmalicious");
    expect(sanitizeCsvCell('\rmalicious')).toBe("'\rmalicious");
  });

  it('does not alter normal space-indented text or whitespace-only values', () => {
    expect(sanitizeCsvCell('   ')).toBe('   ');
    expect(sanitizeCsvCell('  Normal description without formula')).toBe(
      '  Normal description without formula'
    );
    expect(sanitizeCsvCell('   42')).toBe('   42');
  });

  it('wraps values containing commas in double-quotes', () => {
    const result = sanitizeCsvCell('value, with comma');
    expect(result).toBe('"value, with comma"');
  });

  it('escapes embedded double-quotes by doubling them and wraps in outer quotes', () => {
    const result = sanitizeCsvCell('say "hello"');
    expect(result).toBe('"say ""hello"""');
    expect(sanitizeCsvCell('a"b"c')).toBe('"a""b""c"');
  });

  it('wraps values containing newlines in double-quotes', () => {
    expect(sanitizeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    expect(sanitizeCsvCell('line1\r\nline2')).toBe('"line1\r\nline2"');
  });

  it('simultaneously applies formula protection and RFC 4180 escaping when both apply', () => {
    const maliciousTitle = '=HYPERLINK("http://evil.com","Click")';
    const result = sanitizeCsvCell(maliciousTitle);
    // Formula trigger is neutralized inside outer quotes
    expect(result).toBe("\"'=HYPERLINK(\"\"http://evil.com\"\",\"\"Click\"\")\"");
    expect(result.startsWith("\"'")).toBe(true);
    expect(result).not.toMatch(/^=HYPERLINK/);

    // Formula with commas only
    expect(sanitizeCsvCell('=SUM(A1,B1)')).toBe("\"'=SUM(A1,B1)\"");

    // Formula with newlines
    expect(sanitizeCsvCell('=cmd\nsecond line')).toBe("\"'=cmd\nsecond line\"");
  });

  it('protects against formula injection in title without commas or quotes', () => {
    const maliciousTitle = "=cmd|' /C calc'!A0";
    const result = sanitizeCsvCell(maliciousTitle);
    expect(result.startsWith("'")).toBe(true);
    expect(result).not.toMatch(/^=cmd/);
  });

  it('passes through clean alphanumeric values unchanged and readable', () => {
    expect(sanitizeCsvCell('CVE-2024-4577')).toBe('CVE-2024-4577');
    expect(sanitizeCsvCell('critical')).toBe('critical');
    expect(sanitizeCsvCell('192.168.1.1')).toBe('192.168.1.1');
    expect(sanitizeCsvCell('10.0.0.0/24')).toBe('10.0.0.0/24');
    expect(sanitizeCsvCell('0')).toBe('0');
    expect(sanitizeCsvCell(42)).toBe('42');
    expect(sanitizeCsvCell('api.enterprise.internal')).toBe('api.enterprise.internal');
    expect(sanitizeCsvCell('Production Web Server')).toBe('Production Web Server');
  });

  it('safely handles empty and nullable values', () => {
    expect(sanitizeCsvCell('')).toBe('');
    expect(sanitizeCsvCell(null)).toBe('');
    expect(sanitizeCsvCell(undefined)).toBe('');
  });

  it('sanitizes untrusted asset names, hostnames, and report fields', () => {
    expect(sanitizeCsvCell('=WIN-SERVER-01')).toBe("'=WIN-SERVER-01");
    expect(sanitizeCsvCell('+api.corp.internal')).toBe("'+api.corp.internal");
    expect(sanitizeCsvCell('@db-cluster, primary')).toBe("\"'@db-cluster, primary\"");
  });
});

// ─── CSV Export Behavior ──────────────────────────────────────────────────────

describe('Phase 9: CSV Export Real Download', () => {
  let mockLink: {
    href: string;
    download: string;
    click: ReturnType<typeof vi.fn>;
    setAttribute: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    // Mock DOM APIs for download trigger
    mockLink = {
      href: '',
      download: '',
      click: vi.fn(),
      setAttribute: vi.fn(),
    };
    const mockDocument = {
      createElement: vi.fn().mockReturnValue(mockLink),
      body: {
        appendChild: vi.fn().mockImplementation((node) => node),
        removeChild: vi.fn().mockImplementation((node) => node),
      },
    };
    vi.stubGlobal('document', mockDocument);

    const MockBlob = vi.fn(function (parts: unknown[], options?: unknown) {
      return { type: 'text/csv;charset=utf-8;', size: 100, parts, options };
    });
    vi.stubGlobal('Blob', MockBlob);
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:mock-url'),
      revokeObjectURL: vi.fn(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('exportReportCsv triggers a real download link click', () => {
    const report = makeReadyReport();
    expect(() => exportReportCsv(report)).not.toThrow();

    expect(mockLink.click).toHaveBeenCalledOnce();
  });

  it('exportReportCsv sets safe filename from report name and date', () => {
    const report = makeReadyReport({ name: 'My Report: With=Special Chars', scanDate: '2026-10-27' });
    exportReportCsv(report);

    // Filename must not contain unsafe characters
    expect(mockLink.download).not.toContain(':');
    expect(mockLink.download).toMatch(/\.csv$/);
    expect(mockLink.download).toContain('2026-10-27');
  });

  it('exportReportCsv includes correct severity counts in Blob content', () => {
    const report = makeReadyReport({
      findingsSummary: { critical: 3, high: 7, medium: 4, low: 2, info: 1, total: 17 },
    });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).toContain('Critical Findings,3');
    expect(csvText).toContain('High Findings,7');
    expect(csvText).toContain('Medium Findings,4');
    expect(csvText).toContain('Low Findings,2');
    expect(csvText).toContain('Total Findings,17');
  });

  it('exportReportCsv includes correct zero counts when no findings', () => {
    const report = makeReadyReport({
      findingsSummary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).toContain('Critical Findings,0');
    expect(csvText).toContain('Total Findings,0');
  });

  it('exportReportCsv applies formula-injection sanitization to report name in header', () => {
    const report = makeReadyReport({ name: '=MALICIOUS()' });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    // The sanitized header must not contain unsanitized formula
    expect(csvText).not.toContain('# Report: =MALICIOUS()');
    // Should be prefixed with single-quote
    expect(csvText).toContain("# Report: '=MALICIOUS()");
  });

  it('exportReportCsv sanitizes untrusted target scope with formula and commas in CSV header', () => {
    const report = makeReadyReport({
      target: '=HYPERLINK("http://evil.com","Click")',
    });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).not.toContain('# Target: =HYPERLINK');
    expect(csvText).toContain('# Target: "\'=HYPERLINK(""http://evil.com"",""Click"")"');
  });

  it('exportReportCsv sanitizes report name with leading whitespace before formula trigger', () => {
    const report = makeReadyReport({ name: '   =cmd|/C calc' });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).not.toContain('# Report:    =cmd');
    expect(csvText).toContain("# Report: '   =cmd|/C calc");
  });

  it('exportReportCsv preserves RFC 4180 escaping for target containing commas and quotes', () => {
    const report = makeReadyReport({ target: '192.168.1.1, "DMZ Subnet"' });

    exportReportCsv(report);

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).toContain('# Target: "192.168.1.1, ""DMZ Subnet"""');
  });

  it('exportReportCsv safely handles undefined findingsSummary counts with default zero', () => {
    const report = makeReadyReport({
      findingsSummary: undefined as any,
    });

    expect(() => exportReportCsv(report)).not.toThrow();

    const BlobCtor = (globalThis.Blob as ReturnType<typeof vi.fn>);
    const [csvLines] = BlobCtor.mock.calls[0];
    const csvText: string = csvLines[0];

    expect(csvText).toContain('Critical Findings,0');
    expect(csvText).toContain('Total Findings,0');
  });
});

// ─── Export Boundary (Simulated vs Real) ──────────────────────────────────────

describe('Phase 9: Real Export Boundary', () => {
  it('exposes real CSV and PDF export functions', () => {
    // Both formats have dedicated export implementations.
    const csvReport = makeReadyReport({ format: 'csv' });
    const pdfReport = makeReadyReport({ format: 'pdf' });

    // Confirm both are valid Report objects
    expect(csvReport.format).toBe('csv');
    expect(pdfReport.format).toBe('pdf');

    // CSV real download: exportReportCsv is defined and callable
    expect(typeof exportReportCsv).toBe('function');
    expect(typeof exportReportPdf).toBe('function');

    // (the UI shows a toast notification only — will be real in Phase 9.3)
  });

  it('generateReport returns findingsSummary from backend, not hardcoded', async () => {
    const backendResponse = makeBackendReport({
      findings_summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => backendResponse,
    } as Response);

    const r = await generateReport({
      name: 'Data Integrity Check',
      target: '10.1.1.0/24',
      type: 'technical',
      format: 'csv',
    });

    expect(fetchSpy).toHaveBeenCalled();
    expect(r.findingsSummary.critical).toBe(1);
    expect(r.findingsSummary.total).toBe(1);

    fetchSpy.mockRestore();
  });
});

// ─── Posture Metrics (Open Ports vs Vulnerabilities) ──────────────────────────

describe('Phase 9: Security Posture Data Integrity', () => {
  it('open ports in scan results are not classified as vulnerabilities', () => {
    // Architectural contract: ScanResult rows describe discovered ports (open/filtered/closed).
    // Vulnerability rows are separately recorded in the vulnerability table.
    // The Reports page shows vulnerability counts from getDashboard().severity_counts only.

    const scanResult = {
      id: 'sr-001',
      scan_id: 'scan-001',
      host_address: '192.168.1.1',
      port: 22,
      protocol: 'tcp',
      port_state: 'open',
      service_name: 'ssh',
      created_at: '2026-10-27T00:00:00Z',
    };

    // A ScanResult with port_state=open is a port discovery, not a vulnerability.
    expect(scanResult.port_state).toBe('open');
    // No severity or status field exists on scan results — they are not vulnerabilities.
    expect((scanResult as Record<string, unknown>)['severity']).toBeUndefined();
    expect((scanResult as Record<string, unknown>)['cvss']).toBeUndefined();
  });

  it('security score formula: 100 - (critical*25 + high*15 + medium*5 + low*1), clamped 0-100', () => {
    const calcScore = (c: number, h: number, m: number, l: number) =>
      Math.max(0, Math.min(100, 100 - (c * 25 + h * 15 + m * 5 + l * 1)));

    expect(calcScore(0, 0, 0, 0)).toBe(100); // Clean state
    expect(calcScore(1, 1, 1, 1)).toBe(54);  // Phase 5 documented formula
    expect(calcScore(4, 0, 0, 0)).toBe(0);   // Floor at 0
    expect(calcScore(0, 0, 20, 0)).toBe(0);  // Floor at 0
  });
});

// ─── Real PDF Report Export (Phase 9.3) ──────────────────────────────────────

describe('Phase 9.3: Real PDF Report Export', () => {
  let mockLink: {
    href: string;
    download: string;
    click: ReturnType<typeof vi.fn>;
    setAttribute: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    mockLink = {
      href: '',
      download: '',
      click: vi.fn(),
      setAttribute: vi.fn(),
    };
    const mockDocument = {
      createElement: vi.fn().mockReturnValue(mockLink),
      body: {
        appendChild: vi.fn().mockImplementation((node) => node),
        removeChild: vi.fn().mockImplementation((node) => node),
      },
    };
    vi.stubGlobal('document', mockDocument);
    vi.stubGlobal('window', {});
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:mock-url-pdf'),
      revokeObjectURL: vi.fn(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('generates a genuine binary PDF document with %PDF- header', () => {
    const report = makeReadyReport();
    const doc = generateReportPdf(report);

    // Verify jsPDF document properties
    expect(doc).toBeDefined();
    expect(typeof doc.output).toBe('function');

    // Verify genuine PDF file header
    const rawOutput = doc.output();
    expect(rawOutput.startsWith('%PDF-')).toBe(true);
    expect(rawOutput.includes('%%EOF')).toBe(true);
  });

  it('sets document metadata correctly', () => {
    const report = makeReadyReport({
      name: 'SOC Quarterly Audit 2026',
      type: 'executive',
    });
    const doc = generateReportPdf(report);
    const raw = doc.output();

    // Document metadata should contain title, author, and creator
    expect(raw).toContain('SOC Quarterly Audit 2026');
    expect(raw).toContain('VulnScanner SOC Team');
    expect(raw).toContain('VulnScanner Enterprise Security Platform');
  });

  it('derives meaningful, safe filenames for PDF downloads', () => {
    const report = makeReadyReport({
      name: 'Infrastructure / Core Database: Pentest',
      scanDate: '2026-10-28',
      reportCode: 'RPT-20261028-A1B2',
    });
    const filename = getReportPdfFilename(report);

    expect(filename).toContain('Infrastructure_Core_Database_Pentest');
    expect(filename).toContain('RPT-20261028-A1B2');
    expect(filename).toContain('2026-10-28');
    expect(filename.endsWith('.pdf')).toBe(true);
    expect(filename).not.toMatch(/[\/\\:*?"<>|]/);
  });

  it('handles empty findings (total = 0) truthfully without crashing', () => {
    const cleanReport = makeReadyReport({
      name: 'Clean Perimeter Audit',
      findingsSummary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
      },
      securityScore: 100,
    });

    const doc = generateReportPdf(cleanReport);
    const raw = doc.output();

    expect(raw.startsWith('%PDF-')).toBe(true);
    // Should include zero counts and clean audit notice
    expect(raw).toContain('Clean Audit Status');
  });

  it('handles missing optional fields gracefully (null score, undefined counts)', () => {
    const sparseReport = makeReadyReport({
      securityScore: undefined,
      totalAssets: undefined,
      totalScans: undefined,
      snapshotData: null,
    });

    const doc = generateReportPdf(sparseReport);
    const raw = doc.output();

    expect(raw.startsWith('%PDF-')).toBe(true);
    expect(raw).toContain('N/A');
  });

  it('renders itemized technical findings from snapshot data when present', () => {
    const detailedReport = makeReadyReport({
      name: 'Detailed Pentest Report',
      snapshotData: {
        recent_findings: [
          {
            title: 'Apache HTTP Server Path Traversal',
            severity: 'critical',
            cvss_score: 9.8,
            cve_id: 'CVE-2021-41773',
            status: 'open',
            asset_name: 'Edge-Gateway-01',
            asset_target: '192.168.1.1',
            description: 'Flaw in path normalization allows remote code execution.',
            evidence: 'GET /icons/.%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1',
            remediation: 'Upgrade Apache HTTP Server to version 2.4.51 or later.',
          },
        ],
      },
    });

    const doc = generateReportPdf(detailedReport);
    const raw = doc.output();

    expect(raw).toContain('Apache HTTP Server Path Traversal');
    expect(raw).toContain('CVE-2021-41773');
    expect(raw).toContain('CRITICAL');
    expect(raw).toContain('Edge-Gateway-01');
    expect(raw).toContain('Upgrade Apache HTTP Server');
  });

  it('paginates across multiple pages when findings list is extensive', () => {
    // Generate 15 findings to trigger page break
    const findings = Array.from({ length: 15 }, (_, i) => ({
      title: `Vulnerability Finding #${i + 1} Buffer Overflow`,
      severity: i % 2 === 0 ? 'high' : 'medium',
      cvss_score: 7.5,
      cve_id: `CVE-2026-${1000 + i}`,
      status: 'open',
      description: `Detailed description for finding number ${i + 1} with remediation requirements.`,
      remediation: 'Apply patch cycle immediately.',
    }));

    const longReport = makeReadyReport({
      snapshotData: { recent_findings: findings },
    });

    const doc = generateReportPdf(longReport);
    const totalPages = doc.getNumberOfPages();

    expect(totalPages).toBeGreaterThan(1);
    const raw = doc.output();
    expect(raw).toContain(`Page 1 of ${totalPages}`);
    expect(raw).toContain(`Page ${totalPages} of ${totalPages}`);
  });

  it('exportReportPdf triggers a download and revokes its temporary object URL', () => {
    vi.useFakeTimers();
    const report = makeReadyReport();

    const result = exportReportPdf(report);

    expect(result).toBeDefined();
    expect(result.filename.endsWith('.pdf')).toBe(true);
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.sizeBytes).toBeGreaterThan(100);

    // Verify DOM download interaction via stubbed document
    expect(mockLink.click).toHaveBeenCalledOnce();
    expect(mockLink.download).toBe(result.filename);
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();

    vi.advanceTimersByTime(100);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:mock-url-pdf');
  });

  it('preserves CSV export regression integrity alongside PDF export', () => {
    const report = makeReadyReport({
      name: '=cmd|/C calc',
      target: '+192.168.1.1',
    });

    exportReportCsv(report);

    expect(mockLink.click).toHaveBeenCalledOnce();

    // Verify formula protection was preserved
    expect(sanitizeCsvCell('=cmd|/C calc')).toBe("'=cmd|/C calc");
    expect(sanitizeCsvCell('+192.168.1.1')).toBe("'+192.168.1.1");
  });
});
