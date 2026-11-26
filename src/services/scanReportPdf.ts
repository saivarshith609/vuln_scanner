import { jsPDF } from 'jspdf';
import type { ScanReportDetail, ScanReportFinding, ScanReportPort } from '../types';

const PAGE_WIDTH = 210;
const MARGIN = 15;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const BOTTOM = 278;

const value = (input: string | number | null | undefined): string =>
  input === null || input === undefined || input === '' ? 'Unavailable' : String(input);

const formatDate = (input: string | null | undefined): string =>
  input ? new Date(input).toLocaleString() : 'Unavailable';

const formatDuration = (seconds: number | null | undefined): string => {
  if (seconds === null || seconds === undefined) return 'Unavailable';
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return minutes ? `${minutes}m ${remainder}s` : `${remainder}s`;
};

export function getScanReportPdfFilename(report: ScanReportDetail): string {
  const safeTarget = report.target
    .normalize('NFKD')
    .replace(/[^a-zA-Z0-9.-]+/g, '-')
    .replace(/\.{2,}/g, '.')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, 80) || 'target';
  const rawDate = report.completed_at || report.started_at || report.created_at;
  const date = /^\d{4}-\d{2}-\d{2}/.exec(rawDate)?.[0] || 'undated';
  return `VulnScanner_${safeTarget}_${date}.pdf`;
}

export function generateScanReportPdf(report: ScanReportDetail): jsPDF {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  let y = 18;

  const ensureSpace = (height: number, continuation?: () => void) => {
    if (y + height <= BOTTOM) return;
    doc.addPage();
    y = 18;
    continuation?.();
  };
  const heading = (title: string) => {
    ensureSpace(14);
    doc.setFillColor(16, 185, 129);
    doc.rect(MARGIN, y - 4, 2, 8, 'F');
    doc.setTextColor(21, 32, 43);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.text(title, MARGIN + 5, y + 2);
    y += 10;
  };
  const wrapped = (text: string, x: number, width: number, fontSize = 9, color: [number, number, number] = [55, 65, 81]) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(text, width) as string[];
    ensureSpace(lines.length * 4.2 + 2);
    doc.text(lines, x, y);
    y += lines.length * 4.2 + 2;
  };
  const metadataRow = (label: string, content: string) => {
    ensureSpace(7);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(75, 85, 99);
    doc.text(label.toUpperCase(), MARGIN, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(17, 24, 39);
    const lines = doc.splitTextToSize(content, 126) as string[];
    doc.text(lines, MARGIN + 48, y);
    y += Math.max(6, lines.length * 4.2);
  };

  doc.setFillColor(10, 25, 41);
  doc.rect(0, 0, PAGE_WIDTH, 48, 'F');
  doc.setTextColor(52, 211, 153);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('VULNSCANNER', MARGIN, 13);
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.text('Vulnerability Assessment Report', MARGIN, 26);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Target: ${report.target}`, MARGIN, 35, { maxWidth: CONTENT_WIDTH });
  doc.setTextColor(203, 213, 225);
  doc.text(`Scan ID: ${report.scan_id}`, MARGIN, 42);
  y = 59;

  heading('Executive Summary');
  const metrics: Array<[string, string | number]> = [
    ['Ports examined', value(report.summary.total_ports_examined)],
    ['Recorded port entries', report.summary.recorded_port_entries],
    ['Open ports', report.summary.open_ports],
    ['Closed / filtered', report.summary.closed_or_filtered_ports],
    ['Identified services', report.summary.identified_services],
    ['Vulnerability findings', report.summary.findings.total],
    ['Duration', formatDuration(report.duration_seconds)],
  ];
  const boxWidth = (CONTENT_WIDTH - 6) / 2;
  metrics.forEach(([label, content], index) => {
    if (index % 2 === 0) ensureSpace(15);
    const x = MARGIN + (index % 2) * (boxWidth + 6);
    const rowY = y;
    doc.setFillColor(243, 246, 249);
    doc.roundedRect(x, rowY - 4, boxWidth, 12, 2, 2, 'F');
    doc.setTextColor(100, 116, 139);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    doc.text(label.toUpperCase(), x + 4, rowY);
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(10);
    doc.text(String(content), x + boxWidth - 4, rowY + 4, { align: 'right' });
    if (index % 2 === 1 || index === metrics.length - 1) y += 16;
  });
  wrapped(
    `Severity: ${report.summary.findings.critical} critical, ${report.summary.findings.high} high, ${report.summary.findings.medium} medium, ${report.summary.findings.low} low, ${report.summary.findings.info} informational.`,
    MARGIN,
    CONTENT_WIDTH,
  );

  heading('Target and Scan Details');
  metadataRow('Requested target', report.target);
  metadataRow('Resolved addresses', report.resolved_addresses.length ? report.resolved_addresses.join(', ') : 'Unavailable');
  metadataRow('Created', formatDate(report.created_at));
  metadataRow('Started', formatDate(report.started_at));
  metadataRow('Completed', formatDate(report.completed_at));
  metadataRow('Status', `${report.status} (${report.progress}%)`);
  metadataRow('Profile / scanner', `${report.scan_profile} / ${report.scanner}`);
  metadataRow('Configuration', value(report.recorded_configuration));
  metadataRow('Authorization mode', value(report.authorization_mode));
  if (report.error_message) metadataRow('Execution message', report.error_message);
  y += 4;

  const portHeader = () => {
    doc.setFillColor(15, 118, 110);
    doc.rect(MARGIN, y - 4, CONTENT_WIDTH, 8, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    ['PORT', 'PROTO', 'STATE', 'SERVICE', 'PRODUCT / VERSION / DETAILS'].forEach((label, index) => {
      doc.text(label, [MARGIN + 2, 34, 52, 75, 108][index], y + 1);
    });
    y += 7;
  };
  heading('Discovered Ports and Services');
  if (!report.ports.length) {
    const stateText = report.status === 'running'
      ? 'The scan is still running; no port inventory is available yet.'
      : report.status === 'failed'
        ? 'The scan failed before a port inventory was recorded.'
        : report.status === 'cancelled'
          ? 'The scan was cancelled; no port inventory was recorded.'
          : 'The completed scan has no persisted port inventory. This is not evidence that every port was closed.';
    wrapped(stateText, MARGIN, CONTENT_WIDTH);
  } else {
    portHeader();
    report.ports.forEach((port: ScanReportPort) => {
      const details = [port.product, port.version, port.extra_information].filter(Boolean).join(' ') || '—';
      const detailLines = doc.splitTextToSize(details, 84) as string[];
      const rowHeight = Math.max(7, detailLines.length * 3.6 + 2);
      ensureSpace(rowHeight, portHeader);
      doc.setTextColor(31, 41, 55);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.text(value(port.port), MARGIN + 2, y);
      doc.text(value(port.protocol).toUpperCase(), 34, y);
      doc.text(value(port.state), 52, y);
      doc.text(value(port.service_name), 75, y, { maxWidth: 30 });
      doc.text(detailLines, 108, y);
      doc.setDrawColor(226, 232, 240);
      doc.line(MARGIN, y + rowHeight - 3, PAGE_WIDTH - MARGIN, y + rowHeight - 3);
      y += rowHeight;
    });
  }

  const estimateFindingHeight = (finding: ScanReportFinding) => {
    const findingText = [
      `ID: ${finding.id} | CVE: ${value(finding.cve_id)} | CVSS: ${value(finding.cvss_score)} ${finding.cvss_vector || ''} | Status: ${finding.status}`,
      `Affected: ${finding.affected_target}${finding.port ? `:${finding.port}` : ''}${finding.service_name ? ` (${finding.service_name})` : ''}`,
      finding.description ? `Description: ${finding.description}` : '',
      finding.evidence ? `Evidence: ${finding.evidence}` : '',
      finding.remediation ? `Remediation: ${finding.remediation}` : '',
    ].filter(Boolean);
    return 14 + findingText.reduce(
      (height, text) => height + (doc.splitTextToSize(text, CONTENT_WIDTH) as string[]).length * 4.2 + 2,
      0,
    );
  };
  if (report.findings.length) ensureSpace(Math.min(10 + estimateFindingHeight(report.findings[0]), BOTTOM - 18));
  heading('Vulnerability Findings');
  if (!report.findings.length) {
    wrapped('No vulnerability records are linked to this scan. Service observations above are not presented as vulnerabilities.', MARGIN, CONTENT_WIDTH);
  } else {
    report.findings.forEach((finding: ScanReportFinding, index) => {
      ensureSpace(Math.min(estimateFindingHeight(finding), BOTTOM - 18));
      doc.setTextColor(15, 23, 42);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.text(`${index + 1}. ${finding.title}`, MARGIN, y, { maxWidth: CONTENT_WIDTH - 34 });
      doc.setTextColor(180, 50, 50);
      doc.setFontSize(8);
      doc.text(finding.severity.toUpperCase(), PAGE_WIDTH - MARGIN, y, { align: 'right' });
      y += 6;
      wrapped(`ID: ${finding.id} | CVE: ${value(finding.cve_id)} | CVSS: ${value(finding.cvss_score)} ${finding.cvss_vector || ''} | Status: ${finding.status}`, MARGIN, CONTENT_WIDTH, 7.5);
      wrapped(`Affected: ${finding.affected_target}${finding.port ? `:${finding.port}` : ''}${finding.service_name ? ` (${finding.service_name})` : ''}`, MARGIN, CONTENT_WIDTH, 8);
      if (finding.description) wrapped(`Description: ${finding.description}`, MARGIN, CONTENT_WIDTH);
      if (finding.evidence) wrapped(`Evidence: ${finding.evidence}`, MARGIN, CONTENT_WIDTH);
      if (finding.remediation) wrapped(`Remediation: ${finding.remediation}`, MARGIN, CONTENT_WIDTH);
      y += 3;
    });
  }

  heading('Methodology and Limitations');
  wrapped(`Scanner: ${report.scanner}. Profile: ${report.scan_profile}. This report renders persisted records and does not execute a new scan.`, MARGIN, CONTENT_WIDTH);
  report.limitations.forEach((limitation) => wrapped(`- ${limitation}`, MARGIN + 2, CONTENT_WIDTH - 2));

  const pageCount = doc.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(203, 213, 225);
    doc.line(MARGIN, 285, PAGE_WIDTH - MARGIN, 285);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(`Generated ${new Date().toLocaleString()} | Scan ${report.scan_id}`, MARGIN, 290, { maxWidth: 145 });
    doc.text(`Page ${page} of ${pageCount}`, PAGE_WIDTH - MARGIN, 290, { align: 'right' });
  }
  return doc;
}

export function downloadScanReportPdf(report: ScanReportDetail): string {
  const blob = generateScanReportPdf(report).output('blob');
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = getScanReportPdfFilename(report);
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  return anchor.download;
}
