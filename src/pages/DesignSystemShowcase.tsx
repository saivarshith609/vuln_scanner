import React, { useState } from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  CheckCircle2,
  Info,
  Activity,
  Layers,
  Sparkles,
  Search,
  ExternalLink,
  Play,
  RotateCw,
} from 'lucide-react';
import {
  Button,
  Badge,
  SeverityBadge,
  StatusBadge,
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  StatCard,
  ProgressBar,
  Input,
  SearchInput,
  Modal,
} from '../components/ui';
import './DesignSystemShowcase.css';

export const DesignSystemShowcase: React.FC = () => {
  const [searchValue, setSearchValue] = useState('');
  const [inputValue, setInputValue] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [btnLoading, setBtnLoading] = useState(false);
  const [progressVal, setProgressVal] = useState(68);

  const colors = [
    { name: 'Critical Severity', hex: '#EF4444', bg: 'var(--color-critical)' },
    { name: 'High Severity', hex: '#F97316', bg: 'var(--color-high)' },
    { name: 'Medium Severity', hex: '#EAB308', bg: 'var(--color-medium)' },
    { name: 'Low Severity', hex: '#22C55E', bg: 'var(--color-low)' },
    { name: 'Info / Notice', hex: '#06B6D4', bg: 'var(--color-info)' },
    { name: 'Brand Primary', hex: '#3B82F6', bg: 'var(--color-brand)' },
    { name: 'Surface Background', hex: '#0D131F', bg: 'var(--color-bg-surface)' },
    { name: 'Card Background', hex: '#162034', bg: 'var(--color-bg-card)' },
  ];

  return (
    <div className="showcase-container animate-fade-in">
      <header className="showcase-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Badge variant="completed" size="sm">Phase 2 Verification</Badge>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>VulnScan Design System 1.0</span>
        </div>
        <h1 className="showcase-header__title">Design System & Component Library</h1>
        <p className="showcase-header__subtitle">
          Interactive token specifications, typography, severity indicators, and reusable interface primitives.
        </p>
      </header>

      {/* 1. Color Tokens */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <Sparkles size={20} color="var(--color-brand)" /> Color & Severity Tokens
        </h2>
        <div className="showcase-grid-colors">
          {colors.map((c) => (
            <div key={c.name} className="color-swatch">
              <div
                className="color-swatch__preview"
                style={{ backgroundColor: c.bg }}
              />
              <div className="color-swatch__info">
                <span className="color-swatch__name">{c.name}</span>
                <span className="color-swatch__hex">{c.hex}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 2. Badges & Severity */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <ShieldAlert size={20} color="var(--color-critical)" /> Severity & Status Indicators
        </h2>
        <Card>
          <CardHeader
            title="Classification Badges"
            description="Dynamic styling mapped to CVSS severity scores and scanner execution states"
          />
          <CardContent style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '8px' }}>
                CVSS Severity Badges
              </span>
              <div className="showcase-row">
                <SeverityBadge severity="critical" />
                <SeverityBadge severity="high" />
                <SeverityBadge severity="medium" />
                <SeverityBadge severity="low" />
                <SeverityBadge severity="info" />
              </div>
            </div>

            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', display: 'block', marginBottom: '8px' }}>
                Scan Engine Lifecycle Statuses
              </span>
              <div className="showcase-row">
                <StatusBadge status="running" />
                <StatusBadge status="completed" />
                <StatusBadge status="queued" />
                <StatusBadge status="paused" />
                <StatusBadge status="failed" />
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 3. Stat Cards */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <Activity size={20} color="var(--color-brand)" /> Metric Stat Widgets
        </h2>
        <div className="showcase-grid-stats">
          <StatCard
            label="Critical Threats"
            value="14"
            subtitle="Requires immediate patch"
            icon={<Flame size={20} />}
            accent="critical"
            trend={{ value: '+3 today', direction: 'up', isPositive: false }}
          />
          <StatCard
            label="High Severity"
            value="38"
            subtitle="Prioritized for sprint"
            icon={<AlertTriangle size={20} />}
            accent="high"
            trend={{ value: '-5 closed', direction: 'down', isPositive: true }}
          />
          <StatCard
            label="Security Score"
            value="78 / 100"
            subtitle="A- Grade posture"
            icon={<CheckCircle2 size={20} />}
            accent="low"
            trend={{ value: '+4 pts', direction: 'up', isPositive: true }}
          />
          <StatCard
            label="Total Endpoints"
            value="128"
            subtitle="Across 6 target domains"
            icon={<Layers size={20} />}
            accent="brand"
            trend={{ value: '100% active', direction: 'neutral' }}
          />
        </div>
      </section>

      {/* 4. Buttons & Interactive States */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <Layers size={20} color="var(--color-brand)" /> Button Variants & Actions
        </h2>
        <Card>
          <CardContent style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div className="showcase-row">
              <Button variant="primary" leftIcon={<Play size={16} />}>
                Start New Scan
              </Button>
              <Button variant="glow" leftIcon={<Sparkles size={16} />}>
                Glow Action
              </Button>
              <Button variant="secondary">Secondary</Button>
              <Button variant="danger" leftIcon={<ShieldAlert size={16} />}>
                Stop Engine
              </Button>
              <Button variant="outline" rightIcon={<ExternalLink size={16} />}>
                View Report
              </Button>
              <Button variant="ghost">Dismiss</Button>
            </div>

            <div className="showcase-row" style={{ alignItems: 'center' }}>
              <Button
                variant="primary"
                isLoading={btnLoading}
                leftIcon={<RotateCw size={16} />}
                onClick={() => {
                  setBtnLoading(true);
                  setTimeout(() => setBtnLoading(false), 2000);
                }}
              >
                Click to Test Spinner
              </Button>
              <Button size="sm" variant="secondary">Small</Button>
              <Button size="md" variant="secondary">Medium</Button>
              <Button size="lg" variant="secondary">Large</Button>
              <Button variant="secondary" disabled>Disabled State</Button>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 5. Progress Bars */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <Activity size={20} color="var(--color-brand)" /> Progress & Execution Meters
        </h2>
        <Card>
          <CardContent style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <ProgressBar
              value={progressVal}
              label="OWASP Top 10 Web Application Scan"
              variant="primary"
              animated
              size="md"
            />
            <ProgressBar
              value={92}
              label="Critical Vulnerability Mitigation Target"
              variant="critical"
              size="md"
            />
            <ProgressBar
              value={100}
              label="Network Port Reconnaissance"
              variant="low"
              size="sm"
            />
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setProgressVal((prev) => Math.max(0, prev - 15))}
              >
                Decrease
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setProgressVal((prev) => Math.min(100, prev + 15))}
              >
                Increase
              </Button>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* 6. Form Inputs & Modal */}
      <section className="showcase-section">
        <h2 className="showcase-section__title">
          <Search size={20} color="var(--color-brand)" /> Form Controls & Dialogs
        </h2>
        <Card>
          <CardContent style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
            <SearchInput
              value={searchValue}
              onChange={setSearchValue}
              placeholder="Search CVE-2024-xxxx, endpoint..."
            />
            <Input
              label="Target Hostname or IP"
              placeholder="e.g. api.staging.security.internal"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              helperText="RFC 3986 format or IPv4/IPv6 CIDR"
            />
          </CardContent>
          <CardFooter>
            <span style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
              Modal dialog with backdrop blur & focus containment:
            </span>
            <Button variant="primary" onClick={() => setIsModalOpen(true)}>
              Launch Sample Modal
            </Button>
          </CardFooter>
        </Card>
      </section>

      {/* Sample Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Info size={18} color="var(--color-brand)" /> Confirm Target Analysis
          </span>
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setIsModalOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => setIsModalOpen(false)}
            >
              Confirm & Start
            </Button>
          </>
        }
      >
        <p style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: '16px' }}>
          This initiates an automated reconnaissance pipeline against target <code>{inputValue || 'demo-target.domain.internal'}</code>. Active probing may generate security log events in target perimeter IDS/IPS.
        </p>
        <div style={{ background: 'var(--color-bg-surface)', padding: '12px', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>Estimated scan profile:</span>
          <div style={{ marginTop: '6px', display: 'flex', gap: '8px' }}>
            <Badge variant="running">Deep Port Sweep</Badge>
            <Badge variant="info">SSL/TLS Audit</Badge>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default DesignSystemShowcase;
