import React from 'react';
import './ProgressBar.css';

export type ProgressVariant =
  | 'primary'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'gradient';

export interface ProgressBarProps {
  value: number; // 0 to 100
  max?: number;
  label?: string;
  showPercent?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: ProgressVariant;
  animated?: boolean;
  className?: string;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  max = 100,
  label,
  showPercent = true,
  size = 'md',
  variant = 'primary',
  animated = false,
  className = '',
}) => {
  const percentage = Math.min(100, Math.max(0, Math.round((value / max) * 100)));

  return (
    <div className={`vs-progress ${className}`}>
      {(label || showPercent) && (
        <div className="vs-progress__header">
          {label && <span className="vs-progress__label">{label}</span>}
          {showPercent && (
            <span className="vs-progress__percent">{percentage}%</span>
          )}
        </div>
      )}
      <div className={`vs-progress__track vs-progress__track--${size}`}>
        <div
          className={`vs-progress__fill vs-progress__fill--${variant} ${animated ? 'vs-progress__fill--animated' : ''}`}
          style={{ width: `${percentage}%` }}
          role="progressbar"
          aria-valuenow={percentage}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
    </div>
  );
};

export default ProgressBar;
