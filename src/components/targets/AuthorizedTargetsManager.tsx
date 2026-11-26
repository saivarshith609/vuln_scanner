import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  Globe,
  Network,
  Server,
  ToggleLeft,
  ToggleRight,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import type { AuthorizedTarget } from '../../types';
import {
  getAuthorizedTargets,
  createAuthorizedTarget,
  updateAuthorizedTarget,
  deleteAuthorizedTarget,
  ApiError,
} from '../../services/api';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Modal } from '../ui/Modal';
import { Badge } from '../ui/Badge';
import { StateView } from '../ui/StateView';
import { useToast } from '../ui/Toast';
import { validateTargetSyntax, detectTargetType } from '../../utils/targetValidator';
import './AuthorizedTargetsManager.css';

export interface AuthorizedTargetsManagerProps {
  onCountChange?: (total: number, enabled: number) => void;
  className?: string;
}

export const AuthorizedTargetsManager: React.FC<AuthorizedTargetsManagerProps> = ({
  onCountChange,
  className = '',
}) => {
  const { showToast } = useToast();

  const [targets, setTargets] = useState<AuthorizedTarget[]>([]);
  const [loadingState, setLoadingState] = useState<'loading' | 'success' | 'error'>('loading');
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isStale, setIsStale] = useState(false);
  const hasLoadedRef = useRef(false);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'enabled' | 'disabled'>('all');

  // Mutation states
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [targetToDelete, setTargetToDelete] = useState<AuthorizedTarget | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [togglingIds, setTogglingIds] = useState<Set<string>>(new Set());

  // Add Form state
  const [formTarget, setFormTarget] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formEnabled, setFormEnabled] = useState(true);
  const [clientError, setClientError] = useState<string | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);

  const fetchTargets = useCallback(async () => {
    const hasLoaded = hasLoadedRef.current;
    if (!hasLoaded) setLoadingState('loading');
    setIsRefreshing(true);
    setFetchError(null);
    try {
      const res = await getAuthorizedTargets(1, 200, false);
      const items = res?.items || [];
      setTargets(items);
      setLoadingState('success');
      setIsStale(false);
      hasLoadedRef.current = true;
      const enabledCount = items.filter((t) => t.is_enabled).length;
      if (onCountChange) {
        onCountChange(items.length, enabledCount);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch authorized targets.';
      setFetchError(msg);
      setLoadingState(hasLoadedRef.current ? 'success' : 'error');
      setIsStale(hasLoadedRef.current);
    } finally {
      setIsRefreshing(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  // Derived filtered targets
  const filteredTargets = useMemo(() => {
    return targets.filter((item) => {
      const query = searchQuery.trim().toLowerCase();
      const matchQuery =
        !query ||
        item.target.toLowerCase().includes(query) ||
        (item.description || '').toLowerCase().includes(query);

      const matchStatus =
        statusFilter === 'all' ||
        (statusFilter === 'enabled' && item.is_enabled) ||
        (statusFilter === 'disabled' && !item.is_enabled);

      return matchQuery && matchStatus;
    });
  }, [targets, searchQuery, statusFilter]);

  const enabledCount = targets.filter((t) => t.is_enabled).length;
  const disabledCount = targets.length - enabledCount;

  // Handle Create Target
  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);
    setBackendError(null);

    const validation = validateTargetSyntax(formTarget);
    if (!validation.isValid) {
      setClientError(validation.error || 'Invalid target syntax.');
      return;
    }

    setIsSubmitting(true);
    try {
      const created = await createAuthorizedTarget({
        target: formTarget.trim(),
        description: formDescription.trim() || null,
        is_enabled: formEnabled,
      });

      showToast('success', `Target "${created.target}" added to authorization allow-list.`);
      setIsAddOpen(false);
      setFormTarget('');
      setFormDescription('');
      setFormEnabled(true);
      await fetchTargets();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setBackendError(err.message);
      } else if (err instanceof Error) {
        setBackendError(err.message);
      } else {
        setBackendError('An unexpected error occurred while adding the authorized target.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle Toggle Target Status
  const handleToggleStatus = async (item: AuthorizedTarget) => {
    const nextState = !item.is_enabled;
    setTogglingIds((prev) => new Set(prev).add(item.id));
    try {
      await updateAuthorizedTarget(item.id, { is_enabled: nextState });
      showToast(
        'info',
        `Target "${item.target}" is now ${nextState ? 'Authorized / Active' : 'Disabled'}.`
      );
      await fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update target status.';
      showToast('error', msg);
    } finally {
      setTogglingIds((prev) => {
        const next = new Set(prev);
        next.delete(item.id);
        return next;
      });
    }
  };

  // Handle Delete Target
  const handleDeleteConfirm = async () => {
    if (!targetToDelete) return;

    setIsSubmitting(true);
    try {
      await deleteAuthorizedTarget(targetToDelete.id);
      showToast('success', `Target "${targetToDelete.target}" removed from authorization allow-list.`);
      setTargetToDelete(null);
      await fetchTargets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete authorized target.';
      showToast('error', msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getTargetTypeIcon = (target: string) => {
    const type = detectTargetType(target);
    if (type === 'CIDR') return <Network size={14} />;
    if (type === 'Hostname') return <Globe size={14} />;
    return <Server size={14} />;
  };

  return (
    <div className={`vs-auth-targets ${className}`}>
      {/* Header */}
      <div className="vs-auth-targets__header">
        <div className="vs-auth-targets__title-group">
          <h3>
            <ShieldCheck size={20} color="var(--color-brand-light)" />
            Authorized Scan Targets
          </h3>
          <p>
            Manage the explicit allow-list of IP addresses, CIDR ranges, and hostnames authorized for Nmap scanning.
          </p>
        </div>
        <div className="vs-auth-targets__actions">
          <Button
            variant="outline"
            size="sm"
            leftIcon={<RefreshCw size={14} />}
            onClick={fetchTargets}
            isLoading={loadingState === 'loading' || isRefreshing}
          >
            Refresh
          </Button>
          <Button
            variant="primary"
            size="sm"
            leftIcon={<Plus size={14} />}
            onClick={() => {
              setFormTarget('');
              setFormDescription('');
              setFormEnabled(true);
              setClientError(null);
              setBackendError(null);
              setIsAddOpen(true);
            }}
          >
            Authorize Target
          </Button>
        </div>
      </div>

      {/* Scope Notice Banner (Explicit Authorization Enforcement) */}
      <div className="vs-auth-targets__policy-banner" role="region" aria-label="Scope Authorization Policy">
        <ShieldAlert size={22} className="vs-auth-targets__policy-icon" />
        <div className="vs-auth-targets__policy-content">
          <h4>Pre-Authorized Target Scope Policy</h4>
          <p>
            Adding a target authorizes VulnScanner to perform port scans and vulnerability assessments <strong>strictly within the configured target scope</strong>.
            Persistent target authorization does <strong>not</strong> grant permission to scan arbitrary third-party systems or external networks. The scan launcher also supports explicitly confirmed, single-target on-demand scans.
          </p>
        </div>
      </div>

      {/* KPI Chips */}
      <div className="vs-auth-targets__kpi-bar">
        <div className="vs-auth-targets__kpi-chip">
          <span className="vs-auth-targets__kpi-label">Total Allow-Listed:</span>
          <span className="vs-auth-targets__kpi-val">{targets.length}</span>
        </div>
        <div className="vs-auth-targets__kpi-chip">
          <span className="vs-auth-targets__kpi-label">Active / Authorized:</span>
          <span className="vs-auth-targets__kpi-val" style={{ color: 'var(--color-low)' }}>
            {enabledCount}
          </span>
        </div>
        <div className="vs-auth-targets__kpi-chip">
          <span className="vs-auth-targets__kpi-label">Disabled:</span>
          <span className="vs-auth-targets__kpi-val" style={{ color: 'var(--color-medium)' }}>
            {disabledCount}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="vs-auth-targets__filters">
        <div className="vs-auth-targets__search">
          <Input
            placeholder="Search targets or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            leftIcon={<Search size={15} color="var(--color-text-muted)" />}
          />
        </div>
        <select
          className="vs-auth-targets__select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as 'all' | 'enabled' | 'disabled')}
          aria-label="Filter targets by authorization status"
        >
          <option value="all">All Statuses ({targets.length})</option>
          <option value="enabled">Active Only ({enabledCount})</option>
          <option value="disabled">Disabled Only ({disabledCount})</option>
        </select>
      </div>

      {/* Content Area with State Handling */}
      <StateView
        state={loadingState}
        error={fetchError}
        isEmpty={targets.length === 0}
        emptyMessage="No Authorized Scan Targets Configured"
        emptySubtitle="No persistent targets are registered. Add reusable IP, CIDR, or hostname scopes here, or use the scan launcher's confirmed single-target on-demand workflow."
        loadingMessage="Loading authorized scan targets..."
        onRetry={fetchTargets}
        isRefreshing={isRefreshing}
        isStale={isStale}
        staleError={fetchError}
        emptyAction={
          <Button
            variant="primary"
            size="sm"
            leftIcon={<Plus size={14} />}
            onClick={() => setIsAddOpen(true)}
          >
            Authorize First Target
          </Button>
        }
      >
        {/* If targets exist overall, but filter yields 0 */}
        {targets.length > 0 && filteredTargets.length === 0 ? (
          <div
            style={{
              padding: '48px 24px',
              textAlign: 'center',
              background: 'var(--color-bg-card)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-lg)',
            }}
          >
            <p style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '8px' }}>
              No targets match your filter
            </p>
            <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginBottom: '16px' }}>
              No authorized targets found matching &quot;{searchQuery}&quot;.
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSearchQuery('');
                setStatusFilter('all');
              }}
            >
              Reset Filters
            </Button>
          </div>
        ) : (
          <div className="vs-auth-targets__table-card">
            <div className="vs-auth-targets__table-wrapper">
              <table className="vs-auth-targets__table">
                <thead>
                  <tr>
                    <th>Target Scope</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Added On</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTargets.map((item) => {
                    const isToggling = togglingIds.has(item.id);
                    const targetType = detectTargetType(item.target);

                    return (
                      <tr key={item.id}>
                        <td>
                          <span className="vs-auth-targets__target-code">
                            {getTargetTypeIcon(item.target)}
                            {item.target}
                          </span>
                        </td>
                        <td>
                          <span className="vs-auth-targets__type-tag">{targetType}</span>
                        </td>
                        <td>
                          <span style={{ color: item.description ? 'var(--color-text-primary)' : 'var(--color-text-muted)' }}>
                            {item.description || 'No description provided'}
                          </span>
                        </td>
                        <td>
                          {item.is_enabled ? (
                            <Badge variant="low" size="sm" dot>
                              Authorized
                            </Badge>
                          ) : (
                            <Badge variant="paused" size="sm" dot>
                              Disabled
                            </Badge>
                          )}
                        </td>
                        <td>
                          <span className="vs-auth-targets__date">
                            {item.created_at ? new Date(item.created_at).toLocaleDateString(undefined, {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                            }) : '—'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div className="vs-auth-targets__row-actions" style={{ justifyContent: 'flex-end' }}>
                            <button
                              type="button"
                              className={`vs-toggle-btn ${item.is_enabled ? 'vs-toggle-btn--active' : 'vs-toggle-btn--inactive'}`}
                              onClick={() => handleToggleStatus(item)}
                              disabled={isToggling}
                              title={item.is_enabled ? 'Click to disable target' : 'Click to enable target'}
                              aria-label={`Toggle authorization for ${item.target}`}
                            >
                              {item.is_enabled ? (
                                <>
                                  <ToggleRight size={15} />
                                  <span>Enabled</span>
                                </>
                              ) : (
                                <>
                                  <ToggleLeft size={15} />
                                  <span>Disabled</span>
                                </>
                              )}
                            </button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setTargetToDelete(item)}
                              title="Delete authorized target"
                              aria-label={`Delete authorized target ${item.target}`}
                              style={{ color: 'var(--color-critical)', padding: '6px 8px' }}
                            >
                              <Trash2 size={15} />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </StateView>

      {/* Add Target Modal */}
      <Modal
        isOpen={isAddOpen}
        onClose={() => {
          if (!isSubmitting) setIsAddOpen(false);
        }}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={18} color="var(--color-brand-light)" />
            <span>Authorize Scan Target</span>
          </div>
        }
        size="md"
      >
        <form onSubmit={handleCreateTarget} className="vs-auth-form">
          {backendError && (
            <div className="vs-auth-form__error" role="alert">
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>{backendError}</span>
            </div>
          )}

          <div className="vs-auth-form__disclaimer">
            <ShieldAlert size={16} style={{ flexShrink: 0, marginTop: '1px' }} />
            <span>
              <strong>Scope Authorization Disclaimer:</strong> Adding a target allows scans only within this specific target scope. Ensure you own or have explicit written permission to test this host/network.
            </span>
          </div>

          <Input
            label="Target Scope (IP, CIDR, or Hostname) *"
            placeholder="e.g. 127.0.0.1, 10.0.0.0/24, or scanme.nmap.org"
            value={formTarget}
            onChange={(e) => {
              setFormTarget(e.target.value);
              if (clientError) setClientError(null);
              if (backendError) setBackendError(null);
            }}
            error={clientError || undefined}
            helperText="Single IPv4/IPv6, CIDR notation (e.g. 192.168.1.0/24), or RFC-compliant hostname."
            autoFocus
            disabled={isSubmitting}
          />

          <Input
            label="Description / Scope Notes (Optional)"
            placeholder="e.g., Development cluster, Internal bastion host"
            value={formDescription}
            onChange={(e) => setFormDescription(e.target.value)}
            disabled={isSubmitting}
          />

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '12px 14px',
              background: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-md)',
            }}
          >
            <div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Enable Target Immediately
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                When enabled, scans targeting this address or subnet will be permitted.
              </div>
            </div>
            <button
              type="button"
              className={`vs-toggle-btn ${formEnabled ? 'vs-toggle-btn--active' : 'vs-toggle-btn--inactive'}`}
              onClick={() => setFormEnabled(!formEnabled)}
              disabled={isSubmitting}
              aria-label="Toggle enable on creation"
            >
              {formEnabled ? (
                <>
                  <CheckCircle2 size={15} />
                  <span>Enabled</span>
                </>
              ) : (
                <>
                  <ToggleLeft size={15} />
                  <span>Disabled</span>
                </>
              )}
            </button>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
            <Button
              type="button"
              variant="outline"
              size="md"
              onClick={() => setIsAddOpen(false)}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="md"
              isLoading={isSubmitting}
              leftIcon={<Plus size={15} />}
            >
              Authorize Target
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={Boolean(targetToDelete)}
        onClose={() => {
          if (!isSubmitting) setTargetToDelete(null);
        }}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-critical)' }}>
            <Trash2 size={18} />
            <span>Revoke Target Authorization</span>
          </div>
        }
        size="sm"
      >
        {targetToDelete && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              Are you sure you want to remove <strong style={{ color: 'var(--color-text-primary)' }}>{targetToDelete.target}</strong> from the authorization allow-list?
            </p>
            <div
              style={{
                padding: '12px',
                background: 'var(--color-critical-bg)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: 'var(--radius-md)',
                fontSize: '0.8125rem',
                color: '#fca5a5',
              }}
            >
              Any future scans attempting to target this address will be immediately blocked by the scanning engine until re-authorized.
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
              <Button
                variant="outline"
                size="md"
                onClick={() => setTargetToDelete(null)}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                size="md"
                isLoading={isSubmitting}
                onClick={handleDeleteConfirm}
              >
                Confirm Removal
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
