import React, { type ReactElement } from 'react';
import { describe, expect, it } from 'vitest';
import { Button } from '../components/ui/Button';
import { StateView } from '../components/ui/StateView';

describe('Phase 13 UX state contracts', () => {
  it('exposes an accessible initial loading state', () => {
    const view = StateView({
      state: 'loading',
      loadingMessage: 'Loading assets...',
      children: <div />,
    }) as ReactElement<Record<string, unknown>>;

    expect(view.props.role).toBe('status');
    expect(view.props['aria-busy']).toBe('true');
    expect(view.props['aria-live']).toBe('polite');
  });

  it('keeps stale data actionable after a background refresh failure', () => {
    const view = StateView({
      state: 'success',
      isStale: true,
      staleError: 'Server unavailable',
      onRetry: () => {},
      children: <div data-testid="last-known-good" />,
    }) as ReactElement<Record<string, unknown>>;
    const children = React.Children.toArray(view.props.children as React.ReactNode) as ReactElement<Record<string, unknown>>[];

    expect(view.type).toBe(React.Fragment);
    expect(children[0].props.role).toBe('alert');
    expect(JSON.stringify(children[0])).toContain('Server unavailable');
    expect(children[1].props['data-testid']).toBe('last-known-good');
  });

  it('marks pending controls busy and prevents duplicate activation', () => {
    const button = Button({ isLoading: true, children: 'Save' }) as ReactElement<Record<string, unknown>>;

    expect(button.props.disabled).toBe(true);
    expect(button.props['aria-busy']).toBe(true);
  });
});
