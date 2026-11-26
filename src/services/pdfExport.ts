/**
 * VulnScanner — Real PDF Security Report Generator (Phase 9.3)
 *
 * Generates genuine, professional PDF vulnerability assessment reports using jsPDF.
 * Adheres to SOC design system standards:
 * - Proper document metadata (title, author, subject, creator).
 * - Branding header and confidentiality classification notice.
 * - Executive summary with scope parameters and security posture score.
 * - Infrastructure telemetry (assets evaluated, scans in scope).
 * - Vulnerability severity breakdown table with color-coded risk indicators.
 * - Itemized technical findings with CVE, CVSS, affected assets, and remediation (when in snapshot).
 * - Truthful handling of empty findings without fabricated data.
 * - Dynamic pagination with page numbers on all pages.
 * - Browser download with proper object URL revocation.
 */

import { jsPDF } from 'jspdf';
import type { DashboardTelemetry, Report } from '../types';

export interface PdfExportResult {
  filename: string;
  blob: Blob;
  sizeBytes: number;
  downloadInitiated: boolean;
}

export interface DashboardExportAvailability {
  canExport: boolean;
  reason: string | null;
}

export function getDashboardExportAvailability(
  dashboard: DashboardTelemetry | null,
  options: { isStale: boolean; isRefreshing: boolean; isExporting: boolean },
): DashboardExportAvailability {
  if (options.isExporting) {
    return { canExport: false, reason: 'Dashboard PDF generation is already in progress.' };
  }
  if (!dashboard) {
    return { canExport: false, reason: 'Dashboard telemetry has not loaded yet.' };
  }
  if (options.isStale) {
    return { canExport: false, reason: 'Dashboard telemetry is stale. Refresh it before exporting.' };
  }
  if (options.isRefreshing) {
    return { canExport: false, reason: 'Dashboard telemetry is refreshing. Wait for the latest response.' };
  }
  return { canExport: true, reason: null };
}

export function getDashboardPdfFilename(generatedAt: Date = new Date()): string {
  return `vulnscanner-dashboard-${generatedAt.toISOString().slice(0, 10)}.pdf`;
}

export function createDashboardSnapshotReport(
  dashboard: DashboardTelemetry,
  generatedAt: Date = new Date(),
): Report {
  const { stats } = dashboard;
  const generatedIso = generatedAt.toISOString();

  return {
    id: `dashboard-snapshot-${generatedIso}`,
    name: 'VulnScanner Dashboard Telemetry Snapshot',
    target: 'Current platform telemetry',
    type: 'executive',
    scanDate: generatedIso.slice(0, 10),
    status: 'ready',
    format: 'PDF',
    fileSize: '',
    securityScore: stats.securityScore,
    totalAssets: stats.totalAssets,
    totalScans: stats.totalScans,
    findingsSummary: {
      critical: stats.criticalCount,
      high: stats.highCount,
      medium: stats.mediumCount,
      low: stats.lowCount,
      info: stats.infoCount,
      total: stats.totalVulnerabilities,
    },
    snapshotData: {
      document_kind: 'dashboard_snapshot',
      generated_at: generatedIso,
      metrics: {
        total_assets: stats.totalAssets,
        discovered_hosts: stats.discoveredHosts,
        total_scans: stats.totalScans,
        active_scans: stats.activeScans,
        completed_scans: stats.completedScans,
        failed_scans: stats.failedScans,
        cancelled_scans: stats.cancelledScans,
        resolved_vulnerabilities: stats.resolvedCount,
      },
      recent_scans: dashboard.recentScans.map((scan) => ({
        id: scan.id,
        name: scan.name,
        target: scan.targetUrl,
        scan_type: scan.type,
        status: scan.status,
        progress: scan.progress,
        started_at: scan.startedAt,
        completed_at: scan.completedAt,
      })),
      recent_findings: dashboard.recentVulnerabilities.map((vulnerability) => ({
        id: vulnerability.id,
        title: vulnerability.title || vulnerability.name,
        severity: vulnerability.severity,
        cve_id: vulnerability.cve,
        cvss_score: vulnerability.cvssScore ?? vulnerability.cvss,
        status: vulnerability.status,
        asset_name: vulnerability.assetName || vulnerability.asset,
        asset_target: vulnerability.assetTarget || vulnerability.target,
        description: vulnerability.description,
        remediation: vulnerability.remediation,
        discovered_at: vulnerability.discoveredAt,
      })),
    },
  };
}

/**
 * Derives a sanitized, readable filename for the exported PDF.
 */
export function getReportPdfFilename(report: Report): string {
  const safeName = (report.name || 'Security_Report')
    .trim()
    .replace(/[^a-zA-Z0-9_\-]/g, '_')
    .replace(/_+/g, '_');
  const safeDate = (report.scanDate || new Date().toISOString().split('T')[0])
    .trim()
    .replace(/[^a-zA-Z0-9_\-]/g, '_');
  const code = report.reportCode ? `_${report.reportCode.replace(/[^a-zA-Z0-9_\-]/g, '_')}` : '';
  return `${safeName}${code}_${safeDate}.pdf`;
}

/**
 * Builds a genuine jsPDF document containing the complete security report.
 * Does not initiate a download; returns the configured jsPDF instance.
 */
export function generateReportPdf(report: Report): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth(); // 210mm
  const pageHeight = doc.internal.pageSize.getHeight(); // 297mm
  const margin = 15;
  const contentWidth = pageWidth - margin * 2; // 180mm
  const isDashboardSnapshot = report.snapshotData?.document_kind === 'dashboard_snapshot';
  const dashboardMetrics = report.snapshotData?.metrics ?? {};
  const generatedAt = report.snapshotData?.generated_at as string | undefined;

  // Set document metadata
  const docTitle = report.name || 'VulnScanner Security Assessment Report';
  doc.setProperties({
    title: docTitle,
    subject: isDashboardSnapshot
      ? 'Dashboard Telemetry Snapshot'
      : `Security Assessment Report - ${report.type || 'Executive'}`,
    author: 'VulnScanner SOC Team',
    keywords: isDashboardSnapshot
      ? 'security, dashboard, telemetry, soc, snapshot'
      : 'security, vulnerability, assessment, soc, cvss, audit',
    creator: 'VulnScanner Enterprise Security Platform',
  });

  let y = margin;

  // Helper for page overflow check
  const checkPageBreak = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - margin - 15) {
      doc.addPage();
      y = margin + 10;
      return true;
    }
    return false;
  };

  // ─── 1. Header & Branding Banner ───────────────────────────────────────────
  // Dark navy banner at top
  doc.setFillColor(15, 23, 42); // #0f172a
  doc.rect(margin, y, contentWidth, 22, 'F');

  // Accent line on bottom of banner
  doc.setFillColor(59, 130, 246); // #3b82f6
  doc.rect(margin, y + 21, contentWidth, 1, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text('VULNSCANNER ENTERPRISE', margin + 6, y + 9);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184); // #94a3b8
  doc.text(
    isDashboardSnapshot
      ? 'SECURITY OPERATIONS CENTER  //  DASHBOARD TELEMETRY SNAPSHOT'
      : 'SECURITY OPERATIONS CENTER  //  AUTOMATED TELEMETRY AUDIT',
    margin + 6,
    y + 15,
  );

  // Classification & Report Code on right
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(239, 68, 68); // Red
  doc.text('CONFIDENTIAL // TLP:AMBER', pageWidth - margin - 6, y + 8, { align: 'right' });

  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  const displayCode = isDashboardSnapshot
    ? `DASH-${report.scanDate || 'SNAPSHOT'}`
    : report.reportCode || report.id?.slice(0, 16) || 'RPT-AUDIT';
  doc.text(`ID: ${displayCode}`, pageWidth - margin - 6, y + 15, { align: 'right' });

  y += 28;

  // ─── 2. Report Title & Scope Metadata ───────────────────────────────────────
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  const titleLines = doc.splitTextToSize(docTitle, contentWidth);
  doc.text(titleLines, margin, y);
  y += titleLines.length * 7 + 2;

  // Metadata block (2 columns)
  doc.setFillColor(248, 250, 252); // #f8fafc
  doc.setDrawColor(226, 232, 240); // #e2e8f0
  doc.setLineWidth(0.3);
  doc.roundedRect(margin, y, contentWidth, 24, 2, 2, 'FD');

  const col1X = margin + 5;
  const col2X = margin + contentWidth / 2 + 5;

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139); // muted

  // Col 1
  doc.setFont('helvetica', 'bold');
  doc.text(isDashboardSnapshot ? 'DOCUMENT TYPE:' : 'REPORT TYPE:', col1X, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(15, 23, 42);
  doc.text(isDashboardSnapshot ? 'DASHBOARD SNAPSHOT' : (report.type || 'executive').toUpperCase(), col1X + 32, y + 6);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text(isDashboardSnapshot ? 'DATA SCOPE:' : 'TARGET SCOPE:', col1X, y + 12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(15, 23, 42);
  const targetScope = report.target || 'All Authorized Assets';
  doc.text(targetScope.length > 30 ? targetScope.slice(0, 28) + '...' : targetScope, col1X + 32, y + 12);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text('STATUS:', col1X, y + 18);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(34, 197, 94); // green
  doc.text((report.status || 'READY').toUpperCase(), col1X + 32, y + 18);

  // Col 2
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text(isDashboardSnapshot ? 'SNAPSHOT DATE:' : 'SCAN DATE:', col2X, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(15, 23, 42);
  doc.text(report.scanDate || 'Current Assessment', col2X + 28, y + 6);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text('GENERATED:', col2X, y + 12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(15, 23, 42);
  doc.text((generatedAt || new Date().toISOString()).replace('T', ' ').slice(0, 19) + ' UTC', col2X + 28, y + 12);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(100, 116, 139);
  doc.text('FORMAT:', col2X, y + 18);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(15, 23, 42);
  doc.text('PDF (Binary Document)', col2X + 28, y + 18);

  y += 30;

  // ─── 3. Executive Summary ───────────────────────────────────────────────────
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(
    isDashboardSnapshot
      ? '1. DASHBOARD SNAPSHOT SUMMARY'
      : '1. EXECUTIVE SUMMARY & POSTURE ASSESSMENT',
    margin,
    y,
  );
  y += 5;

  const totalFindings = report.findingsSummary?.total ?? 0;
  const crit = report.findingsSummary?.critical ?? 0;
  const high = report.findingsSummary?.high ?? 0;
  const score = report.securityScore !== undefined && report.securityScore !== null
    ? report.securityScore
    : null;

  let summaryParagraph = '';
  if (isDashboardSnapshot) {
    summaryParagraph =
      `This dashboard snapshot captures backend telemetry available at ${generatedAt || report.scanDate}. ` +
      `It records ${report.totalAssets ?? 0} registered assets, ${dashboardMetrics.discovered_hosts ?? 0} discovered hosts, ` +
      `${report.totalScans ?? 0} scan records, and ${totalFindings} confirmed vulnerability finding${totalFindings === 1 ? '' : 's'}. ` +
      `This is a point-in-time telemetry snapshot, not a persisted security report or a complete detailed-findings export.`;
  } else if (totalFindings === 0) {
    summaryParagraph =
      `This security report summarizes the vulnerability assessment performed against "${report.target}". ` +
      `No confirmed security vulnerabilities were identified in the evaluated scope during this scan cycle. ` +
      `The overall infrastructure posture remains within compliant security thresholds with zero high or critical risks.`;
  } else {
    summaryParagraph =
      `This security report summarizes the vulnerability assessment performed against "${report.target}". ` +
      `A total of ${totalFindings} confirmed finding${totalFindings === 1 ? '' : 's'} were identified across ` +
      `the evaluated targets, comprising ${crit} critical, ${high} high, ` +
      `${report.findingsSummary?.medium ?? 0} medium, and ${report.findingsSummary?.low ?? 0} low severity issues. ` +
      (crit > 0
        ? `Immediate remediation is required for ${crit} critical vulnerability finding${crit === 1 ? '' : 's'} to mitigate potential exploitation risks.`
        : `No critical severity exposures were detected; prioritize addressing high and medium findings per standard SLA guidelines.`);
  }

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  const summaryLines = doc.splitTextToSize(summaryParagraph, contentWidth);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 4.5 + 4;

  // ─── 4. KPI Cards ──────────────────────────────────────────────────────────
  const kpiCount = 4;
  const kpiGap = 3;
  const kpiWidth = (contentWidth - kpiGap * (kpiCount - 1)) / kpiCount;
  const kpiHeight = 16;

  const kpis = [
    {
      label: 'SECURITY POSTURE',
      val: score !== null ? `${score}/100` : 'N/A',
      color: score !== null && score >= 80 ? [34, 197, 94] : [239, 68, 68],
    },
    {
      label: 'TOTAL ASSETS',
      val: String(report.totalAssets ?? report.snapshotData?.metrics?.total_assets ?? 0),
      color: [59, 130, 246],
    },
    {
      label: 'SCANS IN SCOPE',
      val: String(report.totalScans ?? report.snapshotData?.metrics?.total_scans ?? 0),
      color: [168, 85, 247],
    },
    {
      label: 'TOTAL FINDINGS',
      val: String(totalFindings),
      color: totalFindings > 0 ? [249, 115, 22] : [34, 197, 94],
    },
  ];

  kpis.forEach((kpi, idx) => {
    const kx = margin + idx * (kpiWidth + kpiGap);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(kx, y, kpiWidth, kpiHeight, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.text(kpi.label, kx + 3, y + 5);

    doc.setFontSize(10.5);
    doc.setTextColor(kpi.color[0], kpi.color[1], kpi.color[2]);
    doc.text(kpi.val, kx + 3, y + 12);
  });

  y += kpiHeight + 8;

  if (isDashboardSnapshot) {
    checkPageBreak(42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('2. SCAN LIFECYCLE & ASSET TELEMETRY', margin, y);
    y += 6;

    const telemetryRows: Array<[string, number]> = [
      ['Discovered Hosts', dashboardMetrics.discovered_hosts ?? 0],
      ['Active / Queued Scans', dashboardMetrics.active_scans ?? 0],
      ['Completed Scans', dashboardMetrics.completed_scans ?? 0],
      ['Failed Scans', dashboardMetrics.failed_scans ?? 0],
      ['Cancelled Scans', dashboardMetrics.cancelled_scans ?? 0],
      ['Resolved Vulnerabilities', dashboardMetrics.resolved_vulnerabilities ?? 0],
    ];

    telemetryRows.forEach(([label, value], index) => {
      const rowY = y + Math.floor(index / 2) * 8;
      const rowX = margin + (index % 2) * (contentWidth / 2);
      const shaded = index % 4 < 2;
      doc.setFillColor(shaded ? 248 : 255, shaded ? 250 : 255, shaded ? 252 : 255);
      doc.rect(rowX, rowY, contentWidth / 2, 8, 'F');
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      doc.text(label, rowX + 4, rowY + 5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(String(value), rowX + contentWidth / 2 - 5, rowY + 5, { align: 'right' });
    });
    y += 28;

    const recentScans = (report.snapshotData?.recent_scans || []) as Array<{
      id?: string;
      name?: string;
      target?: string;
      status?: string;
      started_at?: string;
    }>;
    if (recentScans.length > 0) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(15, 23, 42);
      doc.text('RECENT SCAN ACTIVITY', margin, y);
      y += 5;
      recentScans.slice(0, 5).forEach((scan) => {
        checkPageBreak(7);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.2);
        doc.setTextColor(71, 85, 105);
        const line = `${scan.name || scan.id} | ${scan.target || 'Unknown target'} | ${String(scan.status || 'unknown').toUpperCase()} | ${scan.started_at || 'Start time unavailable'}`;
        const scanLines = doc.splitTextToSize(line, contentWidth - 4);
        doc.text(scanLines, margin + 2, y);
        y += scanLines.length * 3.8 + 2;
      });
      y += 3;
    }
  }

  // ─── 5. Vulnerability Severity Breakdown ────────────────────────────────────
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(isDashboardSnapshot ? '3. VULNERABILITY SEVERITY SUMMARY' : '2. VULNERABILITY SEVERITY BREAKDOWN', margin, y);
  y += 5;

  // Table header
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, y, contentWidth, 7, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text('SEVERITY LEVEL', margin + 4, y + 4.8);
  doc.text('CVSS RANGE', margin + 50, y + 4.8);
  doc.text('FINDINGS COUNT', margin + 90, y + 4.8);
  doc.text('REMEDIATION SLA', margin + 130, y + 4.8);
  y += 7;

  const severityRows = [
    {
      level: 'Critical',
      range: 'CVSS 9.0 - 10.0',
      count: report.findingsSummary?.critical ?? 0,
      sla: '< 24 Hours (Emergency)',
      color: [239, 68, 68],
    },
    {
      level: 'High',
      range: 'CVSS 7.0 - 8.9',
      count: report.findingsSummary?.high ?? 0,
      sla: '< 7 Days (Expedited)',
      color: [249, 115, 22],
    },
    {
      level: 'Medium',
      range: 'CVSS 4.0 - 6.9',
      count: report.findingsSummary?.medium ?? 0,
      sla: '< 30 Days (Scheduled)',
      color: [245, 158, 11],
    },
    {
      level: 'Low',
      range: 'CVSS 0.1 - 3.9',
      count: report.findingsSummary?.low ?? 0,
      sla: '< 90 Days (Routine)',
      color: [16, 185, 129],
    },
    {
      level: 'Informational',
      range: 'CVSS 0.0',
      count: report.findingsSummary?.info ?? 0,
      sla: 'Observational / Triage',
      color: [100, 116, 139],
    },
  ];

  severityRows.forEach((row, i) => {
    const isAlt = i % 2 === 1;
    doc.setFillColor(isAlt ? 248 : 255, isAlt ? 250 : 255, isAlt ? 252 : 255);
    doc.rect(margin, y, contentWidth, 6.5, 'F');

    // Colored bullet
    doc.setFillColor(row.color[0], row.color[1], row.color[2]);
    doc.circle(margin + 5, y + 3.2, 1.2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    doc.text(row.level, margin + 9, y + 4.3);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(row.range, margin + 50, y + 4.3);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(row.count > 0 ? row.color[0] : 100, row.count > 0 ? row.color[1] : 116, row.count > 0 ? row.color[2] : 139);
    doc.text(String(row.count), margin + 95, y + 4.3);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(row.sla, margin + 130, y + 4.3);

    y += 6.5;
  });

  // Total row
  doc.setFillColor(241, 245, 249); // #f1f5f9
  doc.rect(margin, y, contentWidth, 6.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(15, 23, 42);
  doc.text('TOTAL FINDINGS', margin + 9, y + 4.3);
  doc.text(String(totalFindings), margin + 95, y + 4.3);
  y += 10;

  // Empty findings note if total === 0
  if (totalFindings === 0) {
    doc.setFillColor(240, 253, 244); // #f0fdf4
    doc.setDrawColor(187, 247, 208); // #bbf7d0
    doc.roundedRect(margin, y, contentWidth, 10, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(22, 101, 52); // green-800
    doc.text(
      isDashboardSnapshot
        ? '[STATUS] The dashboard endpoint reported zero confirmed vulnerability findings at snapshot time.'
        : '[STATUS] Clean Audit Status: Zero active vulnerability exposures detected for this report scope.',
      margin + 6,
      y + 6,
    );
    y += 14;
  }

  // ─── 6. Itemized Technical Findings (if present in snapshot) ───────────────
  const snapshotFindings: any[] =
    report.snapshotData?.recent_findings ||
    report.snapshotData?.findings ||
    [];

  checkPageBreak(25);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(
    isDashboardSnapshot
      ? '4. RECENT VULNERABILITY ACTIVITY'
      : '3. TECHNICAL FINDINGS & REMEDIATION EVIDENCE',
    margin,
    y,
  );
  y += 5;

  if (snapshotFindings.length === 0) {
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(margin, y, contentWidth, 12, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    const noFindingsMsg =
      isDashboardSnapshot
        ? 'No recent vulnerability records were supplied by the dashboard endpoint for this snapshot.'
        : totalFindings === 0
        ? 'No confirmed vulnerabilities are associated with this audit report. All target services tested compliant.'
        : 'This document represents an executive posture summary. Detailed finding artifacts were not included in the saved snapshot.';
    doc.text(noFindingsMsg, margin + 5, y + 7);
    y += 16;
  } else {
    // List itemized findings from persisted snapshot
    snapshotFindings.forEach((finding, idx) => {
      checkPageBreak(30);

      const sev = (finding.severity || 'info').toLowerCase();
      let badgeColor = [100, 116, 139];
      if (sev === 'critical') badgeColor = [239, 68, 68];
      else if (sev === 'high') badgeColor = [249, 115, 22];
      else if (sev === 'medium') badgeColor = [245, 158, 11];
      else if (sev === 'low') badgeColor = [16, 185, 129];

      // Finding container box
      const boxStartY = y;
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(226, 232, 240);

      // Title & CVE
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      const title = `${idx + 1}. ${finding.title || 'Untitled Finding'}`;
      doc.text(title, margin + 3, y + 5);

      // Severity badge
      doc.setFillColor(badgeColor[0], badgeColor[1], badgeColor[2]);
      doc.roundedRect(pageWidth - margin - 26, y + 1.5, 22, 5, 1, 1, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);
      doc.text(sev.toUpperCase(), pageWidth - margin - 15, y + 5, { align: 'center' });

      y += 8;

      // Meta line: CVE, CVSS, Status, Asset
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      const cveStr = finding.cve_id ? `CVE: ${finding.cve_id}  |  ` : '';
      const cvssStr = finding.cvss_score !== undefined && finding.cvss_score !== null ? `CVSS: ${finding.cvss_score}  |  ` : '';
      const statusStr = finding.status ? `Status: ${finding.status}  |  ` : '';
      const assetStr = finding.asset_name ? `Asset: ${finding.asset_name}` : (finding.asset_target ? `Target: ${finding.asset_target}` : '');
      doc.text(`${cveStr}${cvssStr}${statusStr}${assetStr}`, margin + 3, y);
      y += 4.5;

      // Description if present
      if (finding.description) {
        doc.setTextColor(71, 85, 105);
        doc.setFontSize(7.5);
        const descLines = doc.splitTextToSize(finding.description, contentWidth - 8);
        doc.text(descLines, margin + 3, y);
        y += descLines.length * 3.8 + 2;
      }

      // Evidence / PoC block if present
      if (finding.evidence) {
        doc.setFillColor(241, 245, 249);
        doc.roundedRect(margin + 2, y, contentWidth - 4, 7, 1, 1, 'F');
        doc.setFont('courier', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(30, 41, 59);
        const evSnippet = String(finding.evidence).replace(/\n/g, ' ').slice(0, 100);
        doc.text(`Proof: ${evSnippet}`, margin + 4, y + 4.5);
        y += 9;
      }

      // Remediation guidance if present
      if (finding.remediation) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(34, 197, 94); // green
        doc.text('Remediation: ', margin + 3, y);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        const remLines = doc.splitTextToSize(finding.remediation, contentWidth - 28);
        doc.text(remLines, margin + 22, y);
        y += remLines.length * 3.6 + 2;
      }

      // Border around finding box
      const boxHeight = y - boxStartY + 2;
      doc.setDrawColor(226, 232, 240);
      doc.roundedRect(margin, boxStartY, contentWidth, boxHeight, 1.5, 1.5, 'D');

      y += 5;
    });
  }

  // ─── 7. Footers & Page Numbers on All Pages ─────────────────────────────────
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);

    // Footer divider line
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);

    // Left footer: platform attribution
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(148, 163, 184);
    doc.text(
      isDashboardSnapshot
        ? 'VulnScanner Dashboard Telemetry Snapshot  //  Confidential Document'
        : 'VulnScanner Enterprise Security Assessment  //  Confidential Document',
      margin,
      pageHeight - 7,
    );

    // Right footer: page numbers
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
  }

  return doc;
}

/**
 * Generates and triggers real browser download of the PDF report.
 * Automatically cleans up the object URL after download is dispatched.
 */
function downloadPdf(doc: jsPDF, filename: string): PdfExportResult {
  const blob = doc.output('blob');
  let downloadInitiated = false;

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    downloadInitiated = true;
    document.body.removeChild(link);

    // Ensure temporary browser object URL is cleanly revoked per Phase 9.3 requirements
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 100);
  }

  return {
    filename,
    blob,
    sizeBytes: blob.size,
    downloadInitiated,
  };
}

export function generateDashboardPdf(
  dashboard: DashboardTelemetry,
  generatedAt: Date = new Date(),
): jsPDF {
  return generateReportPdf(createDashboardSnapshotReport(dashboard, generatedAt));
}

export function exportDashboardPdf(
  dashboard: DashboardTelemetry,
  generatedAt: Date = new Date(),
): PdfExportResult {
  return downloadPdf(generateDashboardPdf(dashboard, generatedAt), getDashboardPdfFilename(generatedAt));
}

export function exportReportPdf(report: Report): PdfExportResult {
  return downloadPdf(generateReportPdf(report), getReportPdfFilename(report));
}
