import React from 'react';
import './Skeleton.css';

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  borderRadius?: string;
  variant?: 'text' | 'rectangular' | 'circular';
  className?: string;
  style?: React.CSSProperties;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  width = '100%',
  height = '16px',
  borderRadius,
  variant = 'text',
  className = '',
  style,
}) => {
  const getRadius = () => {
    if (borderRadius) return borderRadius;
    if (variant === 'circular') return '50%';
    if (variant === 'rectangular') return '8px';
    return '4px';
  };

  return (
    <div
      className={`vs-skeleton vs-skeleton--${variant} ${className}`}
      style={{
        width: typeof width === 'number' ? `${width}px` : width,
        height: typeof height === 'number' ? `${height}px` : height,
        borderRadius: getRadius(),
        ...style,
      }}
    />
  );
};

export const SkeletonTable: React.FC<{ rows?: number; columns?: number }> = ({
  rows = 5,
  columns = 6,
}) => {
  return (
    <div className="vs-skeleton-table">
      <div className="vs-skeleton-table-header">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} height={14} width={`${60 + ((i * 17) % 35)}%`} />
        ))}
      </div>
      <div className="vs-skeleton-table-body">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="vs-skeleton-table-row">
            {Array.from({ length: columns }).map((_, c) => (
              <Skeleton
                key={c}
                height={16}
                width={c === 0 ? '80%' : `${50 + ((c * 23) % 40)}%`}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

export const SkeletonCard: React.FC<{ count?: number }> = ({ count = 3 }) => {
  return (
    <div className="vs-skeleton-card-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="vs-skeleton-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <Skeleton width="40%" height={20} />
            <Skeleton width="20%" height={16} borderRadius="12px" />
          </div>
          <Skeleton width="90%" height={14} style={{ marginBottom: '8px' }} />
          <Skeleton width="70%" height={14} style={{ marginBottom: '16px' }} />
          <div style={{ marginTop: 'auto', display: 'flex', gap: '8px' }}>
            <Skeleton width="30%" height={28} borderRadius="6px" />
            <Skeleton width="30%" height={28} borderRadius="6px" />
          </div>
        </div>
      ))}
    </div>
  );
};
