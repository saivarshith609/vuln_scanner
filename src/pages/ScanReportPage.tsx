import React, { useMemo, useRef, useState } from 'react';
import { ArrowLeft, Download, FileSearch, RefreshCw, ShieldCheck } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Badge, StatusBadge } from '../components/ui/Badge';
import { StateView } from '../components/ui/StateView';
import { useToast } from '../components/ui/Toast';
import { useAsync } from '../hooks/useAsync';
import { getScanReport } from '../services/api';
import { downloadScanReportPdf } from '../services/scanReportPdf';
import type { ScanReportDetail, Severity } from '../types';
import './ScanReportPage.css';

interface ScanReportPageProps {
  scanId: string;
  onBack: () => void;
}

const display = (input: string | number | null | undefined) =>
  input === null || input === undefined || input === '' ? 'Unavailable' : String(input);

const dateTime = (input: string | null | undefined) =>
  input ? new Date(input).toLocaleString() : 'Unavailable';

const duration = (seconds: number | null | undefined) => {
  if (seconds === null || seconds === undefined) return 'Unavailable';
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
};

function PortInventoryState({ report }: { report: ScanReportDetail }) {
  if (report.status === 'running') return <>Scan in progress. Port inventory will appear after persisted results are available.</>;
  if (report.status === 'queued') return <>Scan queued. No port inventory has been recorded yet.</>;
  if (report.status === 'failed') return <>Scan failed before a port inventory was recorded{report.error_message ? `: ${report.error_message}` : '.'}</>;
  if (report.status === 'cancelled') return <>Scan cancelled. Any absent inventory must not be interpreted as closed ports.</>;
  return <>Completed scan with no persisted port inventory. This is different from a confirmed result of zero open ports.</>;
}

export const ScanReportPage: React.FC<ScanReportPageProps> = ({ scanId, onBack }) => {
  const { showToast } = useToast();
  const { data: report, state, error, refetch } = useAsync(
    (signal) => getScanReport(scanId, signal),
    [scanId],
  );
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [isDownloading, setIsDownloading] = useState(false);
  const downloadInFlight = useRef(false);

  const findings = useMemo(() => {
    if (!report) return [];
    const needle = query.trim().toLowerCase();
    return report.findings.filter((finding) => {
      const severityMatches = severity === 'all' || finding.severity === severity;
      const searchMatches = !needle || [finding.id, finding.title, finding.cve_id, finding.description]
        .some((field) => field?.toLowerCase().includes(needle));
      return severityMatches && searchMatches;
    });
  }, [query, report, severity]);

  const handleDownload = () => {
    if (!report || downloadInFlight.current) return;
    downloadInFlight.current = true;
    setIsDownloading(true);
    try {
      const filename = downloadScanReportPdf(report);
      showToast('success', `PDF download started: ${filename}`);
    } catch (downloadError) {
      showToast('error', downloadError instanceof Error ? downloadError.message : 'Unable to create the PDF. Please retry.');
    } finally {
      downloadInFlight.current = false;
      setIsDownloading(false);
    }
  };

  if (state === 'loading') {
    return <StateView state="loading" loadingMessage="Building scan report from persisted records…"><div /></StateView>;
  }
  if (state === 'error' || !report) {
    return (
      <StateView state="error" error={error || 'The requested scan report is unavailable.'} onRetry={refetch}>
        <div />
      </StateView>
    );
  }

  const metrics = [
    ['Ports examined', report.summary.total_ports_examined ?? 'Unavailable'],
    ['Recorded entries', report.summary.recorded_port_entries],
    ['Open ports', report.summary.open_ports],
    ['Closed / filtered', report.summary.closed_or_filtered_ports],
    ['Identified services', report.summary.identified_services],
    ['Findings', report.summary.findings.total],
    ['Duration', duration(report.duration_seconds)],
  ];

  return (
    <article className="vs-scan-report" aria-labelledby="scan-report-title">
      <header className="vs-scan-report__hero">
        <div className="vs-scan-report__brand"><ShieldCheck size={18} /> VulnScanner</div>
        <div className="vs-scan-report__header-row">
          <div>
            <h1 id="scan-report-title">Vulnerability Assessment Report</h1>
            <p>{report.target}</p>
            <code>{report.scan_id}</code>
          </div>
          <StatusBadge status={report.status} size="md" />
        </div>
        <div className="vs-scan-report__actions">
          <Button variant="outline" leftIcon={<ArrowLeft size={16} />} onClick={onBack}>Back to scans</Button>
          <Button
            variant="primary"
            leftIcon={<Download size={16} />}
            isLoading={isDownloading}
            disabled={isDownloading}
            onClick={handleDownload}
          >
            Download PDF
          </Button>
        </div>
      </header>

      <section className="vs-scan-report__section" aria-labelledby="summary-heading">
        <h2 id="summary-heading">Executive Summary</h2>
        <div className="vs-scan-report__metrics">
          {metrics.map(([label, metric]) => (
            <div className="vs-scan-report__metric" key={label}>
              <span>{label}</span><strong>{metric}</strong>
            </div>
          ))}
        </div>
        <div className="vs-scan-report__severity-row">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((item) => (
            <Badge key={item} variant={item === 'critical' ? 'critical' : item === 'high' ? 'high' : item === 'medium' ? 'medium' : item === 'low' ? 'low' : 'info'}>
              {item}: {report.summary.findings[item]}
            </Badge>
          ))}
        </div>
      </section>

      <section className="vs-scan-report__section" aria-labelledby="details-heading">
        <h2 id="details-heading">Target and Scan Details</h2>
        <dl className="vs-scan-report__details">
          <div><dt>Requested target</dt><dd>{report.target}</dd></div>
          <div><dt>Resolved IP address</dt><dd>{report.resolved_addresses.length ? report.resolved_addresses.join(', ') : 'Unavailable'}</dd></div>
          <div><dt>Created</dt><dd>{dateTime(report.created_at)}</dd></div>
          <div><dt>Started</dt><dd>{dateTime(report.started_at)}</dd></div>
          <div><dt>Completed</dt><dd>{dateTime(report.completed_at)}</dd></div>
          <div><dt>Profile</dt><dd>{report.scan_profile}</dd></div>
          <div><dt>Scanner</dt><dd>{report.scanner}</dd></div>
          <div><dt>Authorization mode</dt><dd>{display(report.authorization_mode)}</dd></div>
          <div><dt>Recorded configuration</dt><dd>{display(report.recorded_configuration)}</dd></div>
        </dl>
      </section>

      <section className="vs-scan-report__section" aria-labelledby="ports-heading">
        <h2 id="ports-heading">Discovered Ports and Services</h2>
        <p className="vs-scan-report__note">Service discovery is informational. An open port or detected service is not a confirmed vulnerability.</p>
        {!report.ports.length ? (
          <div className="vs-scan-report__empty"><FileSearch size={22} /><PortInventoryState report={report} /></div>
        ) : (
          <div className="vs-scan-report__table-wrap">
            <table>
              <thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service Name</th><th>Product</th><th>Version</th><th>Extra Information</th></tr></thead>
              <tbody>
                {report.ports.map((port) => (
                  <tr key={port.id}>
                    <td><code>{display(port.port)}</code></td><td>{display(port.protocol).toUpperCase()}</td><td>{display(port.state)}</td>
                    <td>{display(port.service_name)}</td><td>{display(port.product)}</td><td>{display(port.version)}</td><td>{display(port.extra_information)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="vs-scan-report__section" aria-labelledby="findings-heading">
        <h2 id="findings-heading">Vulnerability Findings</h2>
        <div className="vs-scan-report__filters">
          <input aria-label="Search findings" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search title, CVE, or description" />
          <select aria-label="Filter findings by severity" value={severity} onChange={(event) => setSeverity(event.target.value as Severity | 'all')}>
            <option value="all">All severities</option>
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </div>
        {!report.findings.length ? (
          <div className="vs-scan-report__empty">No vulnerability records are linked to this scan. No findings have been inferred from port observations.</div>
        ) : !findings.length ? (
          <div className="vs-scan-report__empty">No findings match the current filters.</div>
        ) : findings.map((finding) => (
          <article className="vs-scan-report__finding" key={finding.id}>
            <header><div><code>{finding.id}</code><h3>{finding.title}</h3></div><Badge variant={finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'high' : finding.severity === 'medium' ? 'medium' : finding.severity === 'low' ? 'low' : 'info'}>{finding.severity}</Badge></header>
            <div className="vs-scan-report__finding-meta">
              <span>CVE: {display(finding.cve_id)}</span><span>CVSS: {display(finding.cvss_score)} {finding.cvss_vector || ''}</span>
              <span>Affected: {finding.affected_target}{finding.port ? `:${finding.port}` : ''}{finding.service_name ? ` (${finding.service_name})` : ''}</span><span>Status: {finding.status}</span>
            </div>
            <p><strong>Description:</strong> {display(finding.description)}</p>
            <p><strong>Technical evidence:</strong> {display(finding.evidence)}</p>
            <p><strong>Recommended remediation:</strong> {display(finding.remediation)}</p>
          </article>
        ))}
      </section>

      <section className="vs-scan-report__section" aria-labelledby="method-heading">
        <h2 id="method-heading">Methodology, Recommendations, and Limitations</h2>
        <p>This report renders the records persisted by {report.scanner} using the {report.scan_profile} profile. Opening or downloading it does not execute another scan.</p>
        {report.findings.some((finding) => finding.remediation) && <h3>Recorded recommendations</h3>}
        <ul>
          {report.findings.filter((finding) => finding.remediation).map((finding) => <li key={finding.id}><strong>{finding.severity.toUpperCase()} — {finding.title}:</strong> {finding.remediation}</li>)}
          {report.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
        </ul>
      </section>
      <footer className="vs-scan-report__footer"><RefreshCw size={13} /> Report source: persisted scan, discovery, and vulnerability records.</footer>
    </article>
  );
};

export default ScanReportPage;
