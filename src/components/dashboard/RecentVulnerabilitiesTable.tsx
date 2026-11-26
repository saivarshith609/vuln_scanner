import React, { useState } from 'react';
import { Card, CardHeader, CardContent } from '../ui/Card';
import { SeverityBadge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { SearchInput } from '../ui/Input';
import { Modal } from '../ui/Modal';
import {
  ShieldAlert,
  ExternalLink,
  CheckCircle,
  Copy,
  Terminal,
  FileCode,
} from 'lucide-react';
import type { Vulnerability, Severity } from '../../types';
import './RecentVulnerabilitiesTable.css';

export interface RecentVulnerabilitiesTableProps {
  vulnerabilities: Vulnerability[];
  className?: string;
}

export const RecentVulnerabilitiesTable: React.FC<RecentVulnerabilitiesTableProps> = ({
  vulnerabilities,
  className = '',
}) => {
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');
  const [search, setSearch] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [copied, setCopied] = useState(false);

  const filtered = vulnerabilities.filter((v) => {
    const matchesSeverity = filterSeverity === 'all' || v.severity === filterSeverity;
    const matchesSearch =
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      (v.cve && v.cve.toLowerCase().includes(search.toLowerCase())) ||
      v.target.toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const handleCopyPoC = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className={`vs-findings-card ${className}`}>
      <CardHeader
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={18} color="var(--color-critical)" /> Confirmed Findings & CVE Triage
          </span>
        }
        description="High-priority security vulnerabilities identified during recent scan sweeps"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
              Showing {filtered.length} of {vulnerabilities.length}
            </span>
          </div>
        }
      />

      <CardContent className="vs-findings-card__content">
        {/* Controls: Filter Pills & Search Input */}
        <div className="vs-findings-controls">
          {/* Severity Pills */}
          <div className="vs-findings-filters" role="group" aria-label="Filter findings by severity">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setFilterSeverity(sev)}
                className={`vs-findings-filter ${filterSeverity === sev ? 'vs-findings-filter--active' : ''}`}
                aria-pressed={filterSeverity === sev}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="vs-findings-search">
            <SearchInput
              value={search}
              onChange={setSearch}
              placeholder="Search CVE, endpoint..."
            />
          </div>
        </div>

        {/* Findings Table */}
        <div className="vs-findings-table-wrap">
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                <th style={{ padding: '10px 12px' }}>Vulnerability & CVE</th>
                <th style={{ padding: '10px 12px' }}>CVSS Score</th>
                <th style={{ padding: '10px 12px' }}>Target Asset</th>
                <th style={{ padding: '10px 12px' }}>Discovered</th>
                <th style={{ padding: '10px 12px' }}>Status</th>
                <th style={{ padding: '10px 12px', textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.id}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                    transition: 'background-color 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  {/* Title & CVE */}
                  <td style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                      <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                        {item.title}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        {item.cve && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6875rem', color: 'var(--color-brand-light)' }}>
                            {item.cve}
                          </span>
                        )}
                        <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                          • {item.category}
                        </span>
                      </div>
                    </div>
                  </td>

                  {/* CVSS Badge */}
                  <td style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <SeverityBadge severity={item.severity} size="sm" />
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.8125rem' }}>
                        {item.cvss.toFixed(1)}
                      </span>
                    </div>
                  </td>

                  {/* Target & Path */}
                  <td style={{ padding: '12px', maxWidth: '240px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ color: 'var(--color-text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {item.target}
                      </span>
                      {item.path && (
                        <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.path}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Discovered Age */}
                  <td style={{ padding: '12px', color: 'var(--color-text-muted)' }}>
                    {item.discoveredAt}
                  </td>

                  {/* Status */}
                  <td style={{ padding: '12px' }}>
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        color:
                          item.status === 'open'
                            ? 'var(--color-critical)'
                            : item.status === 'in_progress'
                              ? 'var(--color-medium)'
                              : 'var(--color-low)',
                      }}
                    >
                      {item.status.replace('_', ' ')}
                    </span>
                  </td>

                  {/* Actions */}
                  <td style={{ padding: '12px', textAlign: 'right' }}>
                    <Button
                      variant="outline"
                      size="sm"
                      rightIcon={<ExternalLink size={12} />}
                      onClick={() => setSelectedVuln(item)}
                    >
                      Inspect
                    </Button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td className="vs-findings-empty" colSpan={6}>
                    {vulnerabilities.length === 0
                      ? 'No vulnerabilities recorded in the database. Run a scan to begin finding security issues.'
                      : 'No vulnerabilities match your search query or severity filter.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </CardContent>

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <Modal
          isOpen={!!selectedVuln}
          onClose={() => setSelectedVuln(null)}
          size="lg"
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <SeverityBadge severity={selectedVuln.severity} size="sm" />
              <span>{selectedVuln.cve || selectedVuln.id} — Security Advisory</span>
            </div>
          }
          footer={
            <>
              <Button variant="ghost" onClick={() => setSelectedVuln(null)}>
                Close
              </Button>
              <Button
                variant="primary"
                leftIcon={<CheckCircle size={16} />}
                onClick={() => setSelectedVuln(null)}
              >
                Mark as Remediation Pending
              </Button>
            </>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            <div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                {selectedVuln.title}
              </h3>
              <div style={{ display: 'flex', gap: '12px', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                <span>CVSS Base: <strong style={{ color: '#ffffff' }}>{selectedVuln.cvss}</strong></span>
                <span>Category: <strong style={{ color: '#ffffff' }}>{selectedVuln.category}</strong></span>
                <span>Discovered: <strong style={{ color: '#ffffff' }}>{selectedVuln.discoveredAt}</strong></span>
              </div>
            </div>

            <div style={{ background: 'var(--color-bg-surface)', padding: '14px', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
                Vulnerability Summary
              </span>
              <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.5, fontSize: '0.875rem' }}>
                {selectedVuln.description}
              </p>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
                Affected Asset Endpoint
              </span>
              <code style={{ display: 'block', padding: '10px', background: '#06090e', border: '1px solid var(--color-border)', borderRadius: '6px', fontSize: '0.8125rem', color: 'var(--color-brand-light)' }}>
                {selectedVuln.target}{selectedVuln.path || ''}
              </code>
            </div>

            {selectedVuln.remediation && (
              <div style={{ background: 'rgba(34, 197, 94, 0.08)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(34, 197, 94, 0.25)' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-low)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                  <FileCode size={16} /> Recommended Remediation
                </span>
                <p style={{ color: '#86efac', fontSize: '0.875rem', lineHeight: 1.5 }}>
                  {selectedVuln.remediation}
                </p>
              </div>
            )}

            {/* Proof of Concept Request */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Terminal size={14} /> Reproduce Proof of Concept (cURL)
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyPoC(`curl -i -s -k -X 'GET' '${selectedVuln.target}${selectedVuln.path || ''}'`)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copied ? 'var(--color-low)' : 'var(--color-text-muted)',
                    cursor: 'pointer',
                    fontSize: '0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <Copy size={12} /> {copied ? 'Copied!' : 'Copy cURL'}
                </button>
              </div>
              <pre style={{ margin: 0, padding: '10px', background: '#06090e', border: '1px solid var(--color-border)', borderRadius: '6px', fontSize: '0.75rem', color: '#cbd5e1', overflowX: 'auto' }}>
                curl -i -s -k -X 'GET' '{selectedVuln.target}{selectedVuln.path || ''}'
              </pre>
            </div>
          </div>
        </Modal>
      )}
    </Card>
  );
};

export default RecentVulnerabilitiesTable;
