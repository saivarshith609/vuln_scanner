import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertOctagon, RotateCcw, RefreshCw } from 'lucide-react';
import { Button } from './Button';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(_error: Error, errorInfo: ErrorInfo) {
    if (import.meta.env.DEV) {
      console.error('Uncaught UI error caught by ErrorBoundary.');
    }
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  private handleReload = () => {
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '400px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '48px 24px',
            margin: '24px auto',
            maxWidth: '720px',
            background: 'var(--color-bg-card)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '16px',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '16px',
            }}
          >
            <AlertOctagon size={28} color="var(--color-critical)" />
          </div>

          <h3
            style={{
              fontSize: '1.25rem',
              fontWeight: 700,
              color: 'var(--color-text-primary)',
              marginBottom: '8px',
            }}
          >
            {this.props.fallbackTitle || 'Telemetry Runtime Exception'}
          </h3>

          <p
            style={{
              fontSize: '0.875rem',
              color: 'var(--color-text-secondary)',
              maxWidth: '520px',
              marginBottom: '20px',
              lineHeight: 1.5,
            }}
          >
            An unexpected error interrupted this module. The error has been captured for telemetry diagnostics.
          </p>

          <div style={{ display: 'flex', gap: '12px' }}>
            <Button
              variant="outline"
              size="md"
              leftIcon={<RotateCcw size={16} />}
              onClick={this.handleReset}
            >
              Recover View
            </Button>
            <Button
              variant="primary"
              size="md"
              leftIcon={<RefreshCw size={16} />}
              onClick={this.handleReload}
            >
              Reload Platform
            </Button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
