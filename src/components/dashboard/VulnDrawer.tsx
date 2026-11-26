import React, { useState, useEffect } from 'react';
import { X, Shield, FileText, CheckCircle, AlertCircle, Loader } from 'lucide-react';
import type { Vulnerability, VulnStatus } from '../../types';
import { Button } from '../ui/Button';

export interface VulnDrawerProps {
  vuln: Vulnerability | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChange?: (id: string, status: VulnStatus) => void | Promise<void>;
  isUpdatingStatus?: boolean;
}

const SEVERITY_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  critical: { bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', text: '#fca5a5' },
  high: { bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', text: '#fdba74' },
  medium: { bg: 'rgba(234,179,8,0.1)', border: 'rgba(234,179,8,0.3)', text: '#fde047' },
  low: { bg: 'rgba(34,197,94,0.1)', border: 'rgba(34,197,94,0.3)', text: '#86efac' },
  info: { bg: 'rgba(59,130,246,0.1)', border: 'rgba(59,130,246,0.3)', text: '#93c5fd' },
};

const STATUS_LABELS: Record<VulnStatus, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  false_positive: 'False Positive',
  accepted: 'Accepted Risk',
};

export const VulnDrawer: React.FC<VulnDrawerProps> = ({
  vuln,
  isOpen,
  onClose,
  onStatusChange,
  isUpdatingStatus = false,
}) => {
  const [mounted, setMounted] = useState(false);
  const [visible, setVisible] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'remediation'>('overview');

  useEffect(() => {
    if (isOpen) {
      setMounted(true);
      const timer = setTimeout(() => setVisible(true), 20);
      return () => clearTimeout(timer);
    } else {
      setVisible(false);
      const timer = setTimeout(() => {
        setMounted(false);
        setActiveTab('overview');
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  if (!mounted) return null;

  const sc = vuln ? SEVERITY_COLORS[vuln.severity] || SEVERITY_COLORS.info : SEVERITY_COLORS.info;
  const tabs = ['overview', 'evidence', 'remediation'] as const;
  const cvssValue = vuln?.cvssScore ?? vuln?.cvss;
  const vulnName = vuln?.name || vuln?.title || 'Vulnerability Details';
  const assetName = vuln?.assetName || vuln?.asset || vuln?.assetTarget || vuln?.target || 'Unknown Target';

  // Primary triage statuses; preserve 'accepted' if present
  const availableStatuses: VulnStatus[] = ['open', 'in_progress', 'resolved', 'false_positive'];
  if (vuln?.status === 'accepted') {
    availableStatuses.push('accepted');
  }

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(6,9,14,0.65)',
          backdropFilter: 'blur(6px)',
          WebkitBackdropFilter: 'blur(6px)',
          zIndex: 200,
          opacity: visible ? 1 : 0,
          transition: 'opacity 0.28s ease',
        }}
      />

      {/* Drawer */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(580px, 100vw)',
          maxWidth: '100vw',
          background: 'var(--color-bg-card)',
          borderLeft: '1px solid var(--color-border)',
          zIndex: 201,
          display: 'flex',
          flexDirection: 'column',
          transform: visible ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.32s cubic-bezier(0.16, 1, 0.3, 1)',
          boxShadow: visible ? '-8px 0 32px rgba(0,0,0,0.65), 0 0 24px rgba(59,130,246,0.1)' : 'none',
        }}
      >
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ background: sc.bg, border: `1px solid ${sc.border}`, borderRadius: '8px', padding: '8px' }}>
                <Shield size={18} color={sc.text} />
              </div>
              <div>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)', lineHeight: 1.3 }}>
                  {vulnName}
                </h3>
                <code style={{ fontSize: '0.6875rem', color: 'var(--color-brand-light)' }}>
                  {vuln?.cve || 'Non-CVE Finding'}
                </code>
              </div>
            </div>
            <button
              onClick={onClose}
              aria-label="Close vulnerability drawer"
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--color-text-muted)',
                cursor: 'pointer',
                padding: '6px',
                borderRadius: '6px',
                transition: 'transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), color 0.15s, background-color 0.15s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = 'var(--color-text-primary)';
                e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.08)';
                e.currentTarget.style.transform = 'rotate(90deg)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--color-text-muted)';
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.transform = 'none';
              }}
            >
              <X size={18} />
            </button>
          </div>

          {/* Meta row with CVSS 3.1 & Vector */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.6875rem', fontWeight: 700, padding: '3px 8px', borderRadius: '4px', background: sc.bg, color: sc.text, border: `1px solid ${sc.border}` }}>
              {vuln?.severity.toUpperCase()}
            </span>
            {cvssValue !== undefined && (
              <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', padding: '3px 8px', borderRadius: '4px', background: 'rgba(255,255,255,0.04)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' }}>
                CVSS {cvssValue.toFixed(1)}
              </span>
            )}
            {vuln?.cvssVector && (
              <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', padding: '3px 8px', borderRadius: '4px', background: 'rgba(59,130,246,0.08)', color: 'var(--color-brand-light)', border: '1px solid rgba(59,130,246,0.2)' }}>
                {vuln.cvssVector}
              </span>
            )}
            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>→</span>
            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-secondary)' }}>{assetName}</span>
          </div>
        </div>

        {/* Tab navigation */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--color-border)', padding: '0 20px', overflowX: 'auto' }}>
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '10px 14px',
                background: 'none',
                border: 'none',
                borderBottom: activeTab === tab ? '2px solid var(--color-brand)' : '2px solid transparent',
                color: activeTab === tab ? 'var(--color-brand-light)' : 'var(--color-text-muted)',
                fontSize: '0.8125rem',
                fontWeight: activeTab === tab ? 600 : 400,
                cursor: 'pointer',
                textTransform: 'capitalize',
                transition: 'all 0.15s',
              }}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {vuln && (
            <>
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <>
                  <div style={{ background: 'var(--color-bg-surface)', borderRadius: '10px', padding: '16px', border: '1px solid var(--color-border)' }}>
                    <span style={{ fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--color-text-muted)', display: 'block', marginBottom: '8px' }}>
                      Description
                    </span>
                    <p style={{ fontSize: '0.8125rem', lineHeight: 1.7, color: 'var(--color-text-secondary)' }}>
                      {vuln.description || 'No detailed vulnerability description recorded for this finding.'}
                    </p>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                    {[
                      { label: 'Vulnerability ID', val: vuln.id },
                      { label: 'CVE Identifier', val: vuln.cve || '—' },
                      { label: 'Affected Asset', val: assetName },
                      { label: 'Host / Target IP', val: vuln.assetTarget || vuln.target || '—' },
                      { label: 'Current Status', val: STATUS_LABELS[vuln.status] || vuln.status },
                      { label: 'Discovered', val: vuln.discoveredAt },
                      { label: 'Port / Protocol', val: vuln.port ? `${vuln.port}/${vuln.protocol || 'tcp'}` : '—' },
                      { label: 'Service', val: vuln.service || '—' },
                    ].map(({ label, val }) => (
                      <div key={label} style={{ background: 'var(--color-bg-surface)', borderRadius: '8px', padding: '12px', border: '1px solid var(--color-border)' }}>
                        <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '2px' }}>{label}</span>
                        <span style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--color-text-primary)', wordBreak: 'break-all' }}>{val}</span>
                      </div>
                    ))}
                  </div>

                  {vuln.cvssVector && (
                    <div style={{ background: 'var(--color-bg-surface)', borderRadius: '10px', padding: '14px 16px', border: '1px solid var(--color-border)' }}>
                      <span style={{ fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--color-text-muted)', display: 'block', marginBottom: '4px' }}>
                        CVSS 3.1 Vector String
                      </span>
                      <code style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-brand-light)' }}>
                        {vuln.cvssVector}
                      </code>
                    </div>
                  )}
                </>
              )}

              {/* Evidence Tab */}
              {activeTab === 'evidence' && (
                <div style={{ background: 'var(--color-bg-surface)', borderRadius: '10px', padding: '16px', border: '1px solid var(--color-border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <FileText size={15} color="var(--color-text-muted)" />
                    <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      Proof of Concept / Raw Evidence
                    </span>
                  </div>

                  {vuln.evidence ? (
                    <pre
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.75rem',
                        color: 'var(--color-brand-light)',
                        lineHeight: 1.6,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        padding: '12px',
                        background: 'rgba(0,0,0,0.25)',
                        borderRadius: '6px',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {vuln.evidence}
                    </pre>
                  ) : (
                    <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                      <AlertCircle size={24} style={{ margin: '0 auto 8px auto', opacity: 0.5 }} />
                      <p style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--color-text-secondary)', marginBottom: '4px' }}>
                        No Raw Evidence Recorded
                      </p>
                      <p style={{ fontSize: '0.75rem' }}>
                        No proof-of-concept capture or raw execution payload is attached to this finding.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Remediation Tab */}
              {activeTab === 'remediation' && (
                <>
                  <div style={{ background: 'var(--color-bg-surface)', borderRadius: '10px', padding: '16px', border: '1px solid var(--color-border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                      <CheckCircle size={15} color="#86efac" />
                      <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                        Recommended Remediation
                      </span>
                    </div>

                    {vuln.remediation ? (
                      <p style={{ fontSize: '0.8125rem', lineHeight: 1.7, color: 'var(--color-text-secondary)' }}>
                        {vuln.remediation}
                      </p>
                    ) : (
                      <div style={{ padding: '16px 0', color: 'var(--color-text-muted)' }}>
                        <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>
                          Remediation advisory unavailable for this finding.
                        </p>
                        <p style={{ fontSize: '0.75rem', marginTop: '4px' }}>
                          Refer to official vendor security bulletins or the NVD reference for patch guidance.
                        </p>
                      </div>
                    )}
                  </div>

                  {vuln.references && vuln.references.length > 0 && (
                    <div>
                      <span style={{ fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--color-text-muted)', display: 'block', marginBottom: '8px' }}>
                        External References
                      </span>
                      {vuln.references.map((ref: string, i: number) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            display: 'block',
                            fontSize: '0.75rem',
                            color: 'var(--color-brand-light)',
                            marginBottom: '4px',
                            wordBreak: 'break-all',
                            textDecoration: 'underline',
                          }}
                        >
                          {ref}
                        </a>
                      ))}
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>

        {/* Footer with Persistent Triage Actions */}
        {vuln && onStatusChange && (
          <div style={{ padding: '16px 20px', borderTop: '1px solid var(--color-border)', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginRight: '4px' }}>
              Set Triage Status:
            </span>
            {availableStatuses.map((s) => {
              const isActive = vuln.status === s;
              return (
                <Button
                  key={s}
                  size="sm"
                  variant={isActive ? 'primary' : 'outline'}
                  disabled={isUpdatingStatus || isActive}
                  onClick={() => onStatusChange(vuln.id, s)}
                  leftIcon={isUpdatingStatus && isActive ? <Loader size={12} className="animate-spin" /> : undefined}
                >
                  {STATUS_LABELS[s]}
                </Button>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
};

export default VulnDrawer;
