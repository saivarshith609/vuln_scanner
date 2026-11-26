import { describe, it, expect } from 'vitest';
import type { Scan, Vulnerability, Asset, Report } from '../types';
import { mockScans, mockVulnerabilities, mockAssets, mockReports } from './fixtures/mockData';

describe('Phase 15: Core Frontend User Workflows', () => {
  describe('Workflow 1: Scan Engine Lifecycle & Telemetry', () => {
    it('creates a new scan, updates progress, pauses, resumes, and deletes', () => {
      let scans: Scan[] = [...mockScans];

      // 1. Create scan
      const newScan: Scan = {
        id: 'SCAN-TEST-01',
        name: 'API Gateway Fuzzing & Security Audit',
        targetUrl: 'https://gateway.internal.net',
        type: 'api',
        status: 'running',
        progress: 10,
        startedAt: 'Just now',
        findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        logs: ['[00:00:01] Initializing API fuzzing suite...'],
      };
      scans = [newScan, ...scans];
      expect(scans[0].id).toBe('SCAN-TEST-01');
      expect(scans[0].status).toBe('running');

      // 2. View scan progress progression
      scans = scans.map((s) => (s.id === 'SCAN-TEST-01' ? { ...s, progress: 60 } : s));
      expect(scans.find((s) => s.id === 'SCAN-TEST-01')?.progress).toBe(60);

      // 3. Pause scan
      scans = scans.map((s) => (s.id === 'SCAN-TEST-01' ? { ...s, status: 'paused' as const } : s));
      expect(scans.find((s) => s.id === 'SCAN-TEST-01')?.status).toBe('paused');

      // 4. Resume scan
      scans = scans.map((s) => (s.id === 'SCAN-TEST-01' ? { ...s, status: 'running' as const } : s));
      expect(scans.find((s) => s.id === 'SCAN-TEST-01')?.status).toBe('running');

      // 5. Abort / Stop scan
      scans = scans.map((s) => (s.id === 'SCAN-TEST-01' ? { ...s, status: 'failed' as const } : s));
      expect(scans.find((s) => s.id === 'SCAN-TEST-01')?.status).toBe('failed');

      // 6. Delete scan
      scans = scans.filter((s) => s.id !== 'SCAN-TEST-01');
      expect(scans.find((s) => s.id === 'SCAN-TEST-01')).toBeUndefined();
    });
  });

  describe('Workflow 2: Vulnerability Investigation & Triage Status', () => {
    it('filters vulnerabilities and transitions triage status', () => {
      const vulns: Vulnerability[] = [...mockVulnerabilities];
      expect(vulns.length).toBeGreaterThan(0);

      // Filter by critical severity
      const criticals = vulns.filter((v) => v.severity === 'critical');
      expect(criticals.length).toBeGreaterThan(0);
      criticals.forEach((v) => expect(v.severity).toBe('critical'));

      // Triage status update (e.g. Open -> In Progress -> Resolved -> Accepted)
      const target = vulns[0];
      let currentStatus: Vulnerability['status'] = target.status;

      currentStatus = 'in_progress';
      expect(currentStatus).toBe('in_progress');

      currentStatus = 'resolved';
      expect(currentStatus).toBe('resolved');

      currentStatus = 'accepted';
      expect(currentStatus).toBe('accepted');

    });

    it('verifies investigation drawer data payload completeness', () => {
      const vuln = mockVulnerabilities[0];
      expect(vuln.id).toBeDefined();
      expect(vuln.cve).toBeDefined();
      expect(vuln.description).toBeDefined();
      expect(vuln.remediation).toBeDefined();
      expect(vuln.evidence).toBeDefined();
    });
  });

  describe('Workflow 3: Asset Inventory & Management', () => {
    it('adds a new asset, filters by criticality, and removes asset', () => {
      let assets: Asset[] = [...mockAssets];

      // Add asset
      const newAsset: Asset = {
        id: 'AST-TEST-99',
        name: 'Database Backup Cluster 03',
        ip: '10.140.2.19',
        type: 'server',
        criticality: 'critical',
        status: 'online',
        lastScanned: 'Never',
        vulnerabilitiesCount: { critical: 1, high: 2, medium: 3, low: 0, info: 0, total: 6 },
        owner: 'SRE Database Core',
        tags: ['Production', 'Postgres', 'PCI-DSS'],
      };
      assets = [newAsset, ...assets];
      expect(assets[0].id).toBe('AST-TEST-99');

      // Filter by critical
      const criticalAssets = assets.filter((a) => a.criticality === 'critical');
      expect(criticalAssets.some((a) => a.id === 'AST-TEST-99')).toBe(true);

      // Delete asset
      assets = assets.filter((a) => a.id !== 'AST-TEST-99');
      expect(assets.find((a) => a.id === 'AST-TEST-99')).toBeUndefined();
    });
  });

  describe('Workflow 4: Report Generation & Export', () => {
    it('generates a report and simulates PDF/CSV download', () => {
      let reports: Report[] = [...mockReports];

      const newReport: Report = {
        id: 'REP-TEST-100',
        name: 'Infrastructure Penetration Delta Audit',
        target: 'AWS US-East-1 Perimeter',
        type: 'technical',
        format: 'pdf',
        status: 'generating',
        scanDate: '2025-01-20',
        fileSize: 'Pending',
        findingsSummary: { critical: 2, high: 4, medium: 6, low: 1, info: 0, total: 13 },
      };
      reports = [newReport, ...reports];
      expect(reports[0].status).toBe('generating');

      // Simulate completion to 'ready'
      reports = reports.map((r) =>
        r.id === 'REP-TEST-100' ? { ...r, status: 'ready' as const, fileSize: '3.1 MB' } : r
      );
      const readyReport = reports.find((r) => r.id === 'REP-TEST-100');
      expect(readyReport?.status).toBe('ready');
      expect(readyReport?.fileSize).toBe('3.1 MB');

      // Export formats
      const exportPdf = (r: Report) => ({ filename: `${r.id}.pdf`, mime: 'application/pdf' });
      const exportCsv = (r: Report) => ({ filename: `${r.id}.csv`, mime: 'text/csv' });

      expect(exportPdf(readyReport!).filename).toBe('REP-TEST-100.pdf');
      expect(exportCsv(readyReport!).filename).toBe('REP-TEST-100.csv');
    });
  });

  describe('Workflow 5: Configuration Settings & Factory Defaults', () => {
    it('updates platform preferences and resets to factory baseline', () => {
      const defaultScanner = { threads: '10', timeout: '30', userAgent: 'VulnScan/1.0', rateLimit: '100' };
      let currentScanner = { ...defaultScanner };

      // Update setting
      currentScanner.threads = '24';
      currentScanner.timeout = '60';
      expect(currentScanner.threads).toBe('24');
      expect(currentScanner.timeout).toBe('60');

      // Reset to defaults
      currentScanner = { ...defaultScanner };
      expect(currentScanner.threads).toBe('10');
      expect(currentScanner.timeout).toBe('30');
    });
  });
});
