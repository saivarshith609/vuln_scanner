import { describe, it, expect } from 'vitest';
import { mockScans, mockAssets, mockVulnerabilities } from './fixtures/mockData';

describe('Phase 15: UX States, Filters, and Aggregations Testing', () => {
  it('correctly aggregates high-level security KPI stats', () => {
    const totalScans = mockScans.length;
    const runningScans = mockScans.filter((s) => s.status === 'running').length;
    const completedScans = mockScans.filter((s) => s.status === 'completed').length;
    const totalFindings = mockScans.reduce((acc, s) => acc + s.findings.total, 0);

    expect(totalScans).toBeGreaterThan(0);
    expect(runningScans + completedScans).toBeLessThanOrEqual(totalScans);
    expect(totalFindings).toBeGreaterThan(0);
  });

  it('correctly detects empty states when search criteria yields 0 results', () => {
    const search = 'non_existent_search_query_12345';
    const filteredScans = mockScans.filter(
      (s) =>
        s.name.toLowerCase().includes(search) ||
        s.targetUrl.toLowerCase().includes(search) ||
        s.id.toLowerCase().includes(search)
    );

    expect(filteredScans.length).toBe(0);

    // Reset filters restores data
    const resetSearch = '';
    const restoredScans = mockScans.filter(
      (s) =>
        s.name.toLowerCase().includes(resetSearch) ||
        s.targetUrl.toLowerCase().includes(resetSearch) ||
        s.id.toLowerCase().includes(resetSearch)
    );
    expect(restoredScans.length).toBe(mockScans.length);
  });

  it('verifies CVSS severity ranking and threshold mappings', () => {
    const getCvssSeverity = (score: number) => {
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      if (score > 0.0) return 'low';
      return 'info';
    };

    expect(getCvssSeverity(9.8)).toBe('critical');
    expect(getCvssSeverity(7.5)).toBe('high');
    expect(getCvssSeverity(5.3)).toBe('medium');
    expect(getCvssSeverity(2.1)).toBe('low');
    expect(getCvssSeverity(0.0)).toBe('info');
  });

  it('verifies asset inventory criticality counts match individual records', () => {
    const criticalCount = mockAssets.filter((a) => a.criticality === 'critical').length;
    const highCount = mockAssets.filter((a) => a.criticality === 'high').length;
    const mediumCount = mockAssets.filter((a) => a.criticality === 'medium').length;
    const lowCount = mockAssets.filter((a) => a.criticality === 'low').length;

    expect(criticalCount + highCount + mediumCount + lowCount).toBe(mockAssets.length);
  });

  it('verifies vulnerability triage statuses are valid SOC states', () => {
    const validStatuses = new Set([
      'open',
      'triaged',
      'in_progress',
      'remediated',
      'resolved',
      'accepted',
      'false_positive',
    ]);

    mockVulnerabilities.forEach((v) => {
      expect(validStatuses.has(v.status)).toBe(true);
    });
  });
});
