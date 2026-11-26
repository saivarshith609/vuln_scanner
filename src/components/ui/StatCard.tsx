import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import './StatCard.css';

export type StatAccent = 'critical' | 'high' | 'medium' | 'low' | 'brand';

export interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  accent?: StatAccent;
  trend?: {
    value: string | number;
    direction: 'up' | 'down' | 'neutral';
    isPositive?: boolean; // e.g. decrease in critical vulns is positive
  };
  className?: string;
  onClick?: () => void;
  isLoading?: boolean;
  loadingIndex?: number;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtitle,
  icon,
  accent = 'brand',
  trend,
  className = '',
  onClick,
  isLoading = false,
  loadingIndex = 0,
}) => {
  const content = (
    <>
      <div className="vs-stat-card__content">
        <div className="vs-stat-card__top">
          <span className="vs-stat-card__label" data-label={label}>{label}</span>
          {icon && <div className="vs-stat-card__icon-wrapper">{icon}</div>}
        </div>

        <div className="vs-stat-card__main">
          <span className="vs-stat-card__value">{value}</span>
        </div>

        {(subtitle || trend) && (
          <div className="vs-stat-card__bottom">
            {trend && (
              <span
                className={`vs-stat-card__trend ${
                  trend.direction === 'neutral'
                    ? 'vs-stat-card__trend--neutral'
                    : trend.isPositive
                      ? 'vs-stat-card__trend--down-good'
                      : 'vs-stat-card__trend--up-bad'
                }`}
              >
                {trend.direction === 'up' && <TrendingUp size={12} />}
                {trend.direction === 'down' && <TrendingDown size={12} />}
                {trend.direction === 'neutral' && <Minus size={12} />}
                {trend.value}
              </span>
            )}
            {subtitle && <span>{subtitle}</span>}
          </div>
        )}
      </div>

      {isLoading && (
        <span className="vs-stat-card__loading-layer" aria-hidden="true">
          <i className="vs-stat-card__loading-heading" />
          <i className="vs-stat-card__loading-icon" />
          <i className="vs-stat-card__loading-value" />
          <i className="vs-stat-card__loading-copy" />
        </span>
      )}
    </>
  );

  const classes = `vs-stat-card vs-stat-card--${accent} ${onClick ? 'vs-card--interactive' : ''} ${isLoading ? 'vs-stat-card--loading' : ''} ${className}`;
  const loadingStyle = { '--stat-loading-delay': `${loadingIndex * 420}ms` } as React.CSSProperties;
  if (onClick) {
    return (
      <button type="button" className={classes} style={loadingStyle} onClick={onClick} aria-label={`${label}: ${value}`} aria-busy={isLoading || undefined} disabled={isLoading}>
        {content}
      </button>
    );
  }

  return <div className={classes} style={loadingStyle} aria-busy={isLoading || undefined}>{content}</div>;
};

export default StatCard;
