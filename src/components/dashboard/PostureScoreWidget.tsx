import React from 'react';
import { Card, CardHeader, CardContent } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { ShieldCheck } from 'lucide-react';
import './PostureScoreWidget.css';

export interface PostureScoreWidgetProps {
  score: number; // 0–100, from documented posture formula
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  totalAssets: number;
  activeScans: number;
  className?: string;
}

/**
 * Derive a letter grade and human-readable label from the posture score.
 * Thresholds are defined by Phase 5 spec.
 */
function deriveGrade(score: number): { grade: string; label: string; variant: 'low' | 'medium' | 'high' | 'critical' | 'info' } {
  if (score >= 90) return { grade: 'A', label: 'Hardened', variant: 'low' };
  if (score >= 75) return { grade: 'B', label: 'Defensible', variant: 'low' };
  if (score >= 50) return { grade: 'C', label: 'Moderate Risk', variant: 'medium' };
  if (score >= 25) return { grade: 'D', label: 'Elevated Risk', variant: 'high' };
  return { grade: 'F', label: 'Critical Exposure', variant: 'critical' };
}

export const PostureScoreWidget: React.FC<PostureScoreWidgetProps> = ({
  score,
  totalVulnerabilities,
  criticalCount,
  highCount,
  totalAssets,
  activeScans,
  className = '',
}) => {
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const { grade, label, variant } = deriveGrade(score);

  // Build honest summary text from real finding counts.
  const summaryTitle =
    totalVulnerabilities === 0 ? 'Clean Baseline' : `${totalVulnerabilities} Active Finding${totalVulnerabilities !== 1 ? 's' : ''}`;

  const summaryDesc =
    totalVulnerabilities === 0
      ? 'No confirmed vulnerabilities in the database. Posture score reflects a clean baseline.'
      : `${criticalCount} critical and ${highCount} high severity findings are impacting the security posture score.`;

  return (
    <Card className={`vs-posture-card ${className}`}>
      <CardHeader
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={18} color="var(--color-brand)" /> Security Posture Index
          </span>
        }
        action={<Badge variant={variant} size="sm">{grade} · {label}</Badge>}
      />
      <CardContent style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div className="vs-posture__main">
          {/* Radial Meter */}
          <div className="vs-score-gauge">
            <svg>
              <defs>
                <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#3b82f6" />
                  <stop offset="100%" stopColor="#22c55e" />
                </linearGradient>
              </defs>
              <circle
                className="vs-score-gauge__bg"
                cx="60"
                cy="60"
                r={radius}
              />
              <circle
                className="vs-score-gauge__meter"
                cx="60"
                cy="60"
                r={radius}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
              />
            </svg>
            <div className="vs-score-gauge__content">
              <span className="vs-score-gauge__number">{score}</span>
              <span className="vs-score-gauge__grade">/ 100</span>
            </div>
          </div>

          {/* Assessment Summary */}
          <div className="vs-posture__summary">
            <span className="vs-posture__title">{summaryTitle}</span>
            <p className="vs-posture__desc">{summaryDesc}</p>
          </div>
        </div>

        {/* Telemetry Footer — live data only; no MTTR/Coverage (not in backend) */}
        <div className="vs-posture__metrics">
          <div className="vs-posture__stat">
            <span className="vs-posture__stat-val">{totalAssets}</span>
            <span className="vs-posture__stat-label">Assets</span>
          </div>
          <div className="vs-posture__stat">
            <span
              className="vs-posture__stat-val"
              style={{ color: activeScans > 0 ? 'var(--color-brand-light)' : undefined }}
            >
              {activeScans}
            </span>
            <span className="vs-posture__stat-label">Active Scans</span>
          </div>
          <div className="vs-posture__stat">
            <span
              className="vs-posture__stat-val"
              style={{ color: totalVulnerabilities > 0 ? 'var(--color-high)' : 'var(--color-low)' }}
            >
              {totalVulnerabilities}
            </span>
            <span className="vs-posture__stat-label">Findings</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default PostureScoreWidget;
