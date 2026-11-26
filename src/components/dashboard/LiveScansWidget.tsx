import React from 'react';
import { Card, CardHeader, CardContent } from '../ui/Card';
import { ProgressBar } from '../ui/ProgressBar';
import { StatusBadge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { RadarPing } from '../ui/RadarPing';
import { ScanSearch, ArrowRight } from 'lucide-react';
import type { Scan } from '../../types';
import './LiveScansWidget.css';

export interface LiveScansWidgetProps {
  scans: Scan[];
  activeScanCount: number;
  activityIsStale?: boolean;
  onViewAllScans: () => void;
  className?: string;
}

export const LiveScansWidget: React.FC<LiveScansWidgetProps> = ({
  scans,
  activeScanCount,
  activityIsStale = false,
  onViewAllScans,
  className = '',
}) => {
  const hasLiveActivity = activeScanCount > 0 && !activityIsStale;

  return (
    <Card className={`vs-live-scans ${className}`}>
      <CardHeader
        title={
          <span className="vs-live-scans__title">
            <RadarPing active={hasLiveActivity} />
            <ScanSearch className={hasLiveActivity ? 'vs-live-scans__scan-icon--active' : ''} size={18} />
            Live Scan Execution
            <span
              className={`vs-live-scans__activity ${hasLiveActivity ? 'vs-live-scans__activity--active' : ''}`}
              role="status"
              aria-live="polite"
              aria-atomic="true"
            >
              {activityIsStale ? 'Stale' : activeScanCount > 0 ? `${activeScanCount} active` : 'Idle'}
            </span>
          </span>
        }
        description="Recent scan jobs from the database — run a new scan to see live progress"
        action={
          <Button
            variant="ghost"
            size="md"
            className="vs-live-scans__all-button"
            rightIcon={<ArrowRight size={15} />}
            onClick={onViewAllScans}
          >
            All Scans
          </Button>
        }
      />
      <CardContent className="vs-live-scans__content">
        {scans.length === 0 ? (
          <div className="vs-live-scans__empty">
            <span className="vs-live-scans__empty-icon"><ScanSearch size={22} /></span>
            <strong>No scan activity yet</strong>
            <span>Launch a new scan to monitor perimeter security in real time.</span>
          </div>
        ) : (
          scans.map((scan) => (
            <div key={scan.id} className={`vs-live-scans__row vs-live-scans__row--${scan.status}`}>
              <div className="vs-live-scans__row-header">
                <div className="vs-live-scans__identity">
                  <div className="vs-live-scans__name-line">
                    <span className="vs-live-scans__name">{scan.name}</span>
                    <StatusBadge status={scan.status} size="sm" />
                  </div>
                  <span className="vs-live-scans__meta">
                    {scan.targetUrl}
                    {scan.duration ? ` · ${scan.duration}` : ''}
                    {scan.startedAt ? ` · Started ${scan.startedAt}` : ''}
                  </span>
                </div>
              </div>

              <div className="vs-live-scans__progress">
                <ProgressBar
                  value={scan.progress}
                  variant={
                    scan.status === 'running'
                      ? 'primary'
                      : scan.status === 'failed'
                        ? 'critical'
                        : scan.status === 'completed'
                          ? 'low'
                          : 'medium'
                  }
                  animated={scan.status === 'running'}
                  size="sm"
                />
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
};

export default LiveScansWidget;
