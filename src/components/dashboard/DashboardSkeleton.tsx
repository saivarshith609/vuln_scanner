import React from 'react';
import { AlertTriangle, CheckCircle2, Flame, ScanSearch } from 'lucide-react';
import './DashboardSkeleton.css';

interface SkeletonCardProps {
  label: string;
  icon: React.ReactNode;
  accent: string;
  index: number;
}

export const SkeletonCard: React.FC<SkeletonCardProps> = ({ label, icon, accent, index }) => (
  <div
    className="vs-dashboard-skeleton__card"
    style={{
      '--skeleton-accent': accent,
      '--skeleton-delay': `${index * 420}ms`,
    } as React.CSSProperties}
    aria-hidden="true"
  >
    <div className="vs-dashboard-skeleton__card-top">
      <span className="vs-dashboard-skeleton__card-label">{label}</span>
      <span className="vs-dashboard-skeleton__card-icon">{icon}</span>
    </div>
    <div className="vs-dashboard-skeleton__card-body">
      <span className="vs-dashboard-skeleton__card-value" />
      <span className="vs-dashboard-skeleton__card-copy" />
    </div>
  </div>
);

export const SkeletonPanel: React.FC = () => (
  <div className="vs-dashboard-skeleton__panel" aria-hidden="true">
    <span className="vs-dashboard-skeleton__line vs-dashboard-skeleton__line--heading" />
    <div className="vs-dashboard-skeleton__panel-body">
      <span className="vs-dashboard-skeleton__block" />
    </div>
  </div>
);

const loadingCards = [
  { label: 'Critical Exploits', icon: <Flame size={20} />, accent: 'var(--color-critical)' },
  { label: 'High Severity Flaws', icon: <AlertTriangle size={20} />, accent: 'var(--color-high)' },
  { label: 'Total Findings', icon: <CheckCircle2 size={20} />, accent: 'var(--color-low)' },
  { label: 'Scan Engine', icon: <ScanSearch size={20} />, accent: 'var(--color-brand)' },
];

export const DashboardSkeleton: React.FC = () => (
  <div className="vs-dashboard-skeleton" role="status" aria-live="polite" aria-label="Loading dashboard telemetry">
    <span className="sr-only">Connecting to Security Telemetry API...</span>
    <div className="vs-dashboard-skeleton__cards">
      {loadingCards.map((card, index) => <SkeletonCard key={card.label} {...card} index={index} />)}
    </div>
    <div className="vs-dashboard-skeleton__panels">
      <SkeletonPanel />
      <SkeletonPanel />
    </div>
  </div>
);

export default DashboardSkeleton;
