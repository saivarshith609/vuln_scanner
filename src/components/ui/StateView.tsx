import React from 'react';
import { AlertTriangle, RefreshCw, SearchX } from 'lucide-react';
import { Button } from './Button';
import { Skeleton } from './Skeleton';
import type { LoadingState } from '../../hooks/useAsync';

interface StateViewProps {
  state: LoadingState;
  error?: string | null;
  emptyMessage?: string;
  emptySubtitle?: string;
  loadingMessage?: string;
  isEmpty?: boolean;
  isRefreshing?: boolean;
  isStale?: boolean;
  staleError?: string | null;
  lastUpdated?: number | null;
  onRetry?: () => void;
  emptyAction?: React.ReactNode;
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export const StateView: React.FC<StateViewProps> = ({
  state,
  error,
  emptyMessage = 'No data found.',
  emptySubtitle = 'Try adjusting your filters or adding new items.',
  loadingMessage = 'Loading data...',
  isEmpty = false,
  isRefreshing = false,
  isStale = false,
  staleError,
  lastUpdated,
  onRetry,
  emptyAction,
  icon,
  children,
}) => {
  if (state === 'loading' || state === 'idle') {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-busy="true"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '64px 24px',
          gap: '12px',
          color: 'var(--color-text-muted)',
        }}
      >
        <div style={{ width: 'min(100%, 420px)', display: 'flex', flexDirection: 'column', gap: '10px' }} aria-hidden="true">
          <Skeleton width="72%" height={18} />
          <Skeleton width="100%" height={12} />
          <Skeleton width="88%" height={12} />
        </div>
        <span style={{ fontSize: '0.875rem' }}>{loadingMessage}</span>
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div
        role="alert"
        aria-live="assertive"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '64px 24px',
          gap: '14px',
          background: 'var(--color-bg-card)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          borderRadius: '16px',
          margin: '12px 0',
        }}
      >
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '50%',
            background: 'var(--color-critical-bg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: '1px solid rgba(239, 68, 68, 0.3)',
          }}
        >
          <AlertTriangle size={24} color="var(--color-critical)" />
        </div>
        <div style={{ textAlign: 'center' }}>
          <p style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
            Unable to load data
          </p>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', maxWidth: '400px' }}>
            {error || 'An unexpected error occurred while communicating with the telemetry service.'}
          </p>
        </div>
        {onRetry && (
          <Button variant="outline" size="sm" leftIcon={<RefreshCw size={14} />} onClick={onRetry}>
            Retry Request
          </Button>
        )}
      </div>
    );
  }

  if (state === 'success' && isEmpty) {
    return (
      <div
        aria-busy={isRefreshing || undefined}
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '64px 24px',
          gap: '14px',
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: '16px',
        }}
      >
        {isStale && (
          <div
            role="alert"
            aria-live="assertive"
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '10px 14px',
              marginBottom: '4px',
              borderRadius: '10px',
              border: '1px solid rgba(234,179,8,0.35)',
              background: 'rgba(234,179,8,0.08)',
              color: 'var(--color-warning)',
              fontSize: '0.8125rem',
            }}
          >
            Showing the last successful result. {staleError || error || 'Refresh failed.'}
            {onRetry && <Button variant="ghost" size="sm" onClick={onRetry}>Retry</Button>}
          </div>
        )}
        <div
          style={{
            width: '52px',
            height: '52px',
            borderRadius: '50%',
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {icon || <SearchX size={24} color="var(--color-text-muted)" />}
        </div>
        <div style={{ textAlign: 'center' }}>
          <p style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
            {emptyMessage}
          </p>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', maxWidth: '420px' }}>
            {emptySubtitle}
          </p>
        </div>
        {emptyAction && <div style={{ marginTop: '4px' }}>{emptyAction}</div>}
      </div>
    );
  }

  return (
    <>
      {(isStale || isRefreshing) && (
        <div
          role={isStale ? 'alert' : 'status'}
          aria-live={isStale ? 'assertive' : 'polite'}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            padding: '10px 14px',
            marginBottom: '12px',
            borderRadius: '10px',
            border: `1px solid ${isStale ? 'rgba(234,179,8,0.35)' : 'var(--color-border)'}`,
            background: isStale ? 'rgba(234,179,8,0.08)' : 'var(--color-bg-card)',
            color: isStale ? 'var(--color-warning)' : 'var(--color-text-muted)',
            fontSize: '0.8125rem',
          }}
        >
          <span>
            {isStale
              ? `Showing the last successful result. ${staleError || error || 'Refresh failed.'}`
              : 'Refreshing data…'}
            {lastUpdated ? ` Last updated ${new Date(lastUpdated).toLocaleTimeString()}.` : ''}
          </span>
          {onRetry && (
            <Button variant="ghost" size="sm" onClick={onRetry} isLoading={isRefreshing}>
              Retry
            </Button>
          )}
        </div>
      )}
      {children}
    </>
  );
};

export default StateView;
