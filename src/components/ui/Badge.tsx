import React from 'react';
import type { Severity, ScanStatus } from '../../types';
import './Badge.css';

export type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'running'
  | 'completed'
  | 'failed'
  | 'queued'
  | 'paused'
  | 'cancelled'
  | 'idle';

export interface BadgeProps {
  variant: BadgeVariant;
  size?: 'sm' | 'md';
  dot?: boolean;
  pulse?: boolean;
  children: React.ReactNode;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  variant,
  size = 'md',
  dot = true,
  pulse = false,
  children,
  className = '',
}) => {
  return (
    <span className={`vs-badge vs-badge--${variant} vs-badge--${size} ${className}`}>
      {dot && (
        <span
          className={`vs-badge__dot ${pulse || variant === 'running' ? 'vs-badge__dot--pulse' : ''}`}
          aria-hidden="true"
        />
      )}
      <span>{children}</span>
    </span>
  );
};

export const SeverityBadge: React.FC<{
  severity: Severity;
  size?: 'sm' | 'md';
  pulse?: boolean;
  className?: string;
}> = ({ severity, size = 'md', pulse, className }) => {
  return (
    <Badge
      variant={severity}
      size={size}
      pulse={pulse || severity === 'critical'}
      className={className}
    >
      {severity}
    </Badge>
  );
};

export const StatusBadge: React.FC<{
  status: ScanStatus;
  size?: 'sm' | 'md';
  className?: string;
}> = ({ status, size = 'md', className }) => {
  return (
    <Badge
      variant={status}
      size={size}
      pulse={status === 'running'}
      className={className}
    >
      {status}
    </Badge>
  );
};

export default Badge;
