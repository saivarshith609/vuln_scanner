import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  Shield,
  LayoutDashboard,
  ScanSearch,
  AlertTriangle,
  Globe2,
  Network,
  FileText,
  Settings,
  Palette,
  ChevronLeft,
  ChevronRight,
  X,
  UserCog,
  LogOut,
} from 'lucide-react';
import { RadarPing } from '../components/ui/RadarPing';
import { useScans } from '../store/ScanContext';
import { getActiveScanCount } from '../utils/scanActivity';
import './Sidebar.css';
import { useAuth } from '../components/auth/authContext';

export type NavTabId =
  | 'dashboard'
  | 'scans'
  | 'discovery'
  | 'vulnerabilities'
  | 'targets'
  | 'reports'
  | 'settings'
  | 'admin'
  | 'design-system';

export interface SidebarProps {
  currentTab: NavTabId;
  onSelectTab: (tab: NavTabId) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen = false,
  onCloseMobile,
}) => {
  const navRef = useRef<HTMLElement>(null);
  const [activeIndicator, setActiveIndicator] = useState({ top: 0, height: 20, visible: false });
  const { scans, isLoading, isRefreshing, isStale, error } = useScans();
  const { user, logout } = useAuth();
  const activeScanCount = useMemo(() => getActiveScanCount(scans), [scans]);
  const hasActiveScans = activeScanCount > 0;
  const telemetryUnavailable = Boolean(error) && scans.length === 0;
  const telemetryIsStale = isStale || telemetryUnavailable;
  const shouldAnimateRadar = hasActiveScans && !telemetryIsStale;
  let scannerStatus: 'SCANNING' | 'SYNCING' | 'STALE' | 'IDLE' = 'IDLE';
  let scannerDetail = 'No active scan jobs';

  if (isLoading && scans.length === 0) {
    scannerStatus = 'SYNCING';
    scannerDetail = 'Refreshing scan telemetry…';
  } else if (telemetryUnavailable) {
    scannerStatus = 'STALE';
    scannerDetail = 'Scan telemetry unavailable';
  } else if (isStale) {
    scannerStatus = 'STALE';
    scannerDetail = 'Last-known scan telemetry is stale';
  } else if (hasActiveScans) {
    scannerStatus = 'SCANNING';
    scannerDetail = `${activeScanCount} active scan ${activeScanCount === 1 ? 'job' : 'jobs'}`;
  } else if (isRefreshing) {
    scannerStatus = 'SYNCING';
    scannerDetail = 'Refreshing scan telemetry…';
  }

  const mainNavItems = [
    {
      id: 'dashboard' as NavTabId,
      label: 'Dashboard',
      icon: LayoutDashboard,
    },
    {
      id: 'scans' as NavTabId,
      label: 'Scans',
      icon: ScanSearch,
      badge: shouldAnimateRadar ? `${activeScanCount} active` : undefined,
      badgeType: 'brand' as const,
    },
    {
      id: 'discovery' as NavTabId,
      label: 'Network Discovery',
      icon: Network,
    },
    {
      id: 'vulnerabilities' as NavTabId,
      label: 'Vulnerabilities',
      icon: AlertTriangle,
    },
    {
      id: 'targets' as NavTabId,
      label: 'Target Assets',
      icon: Globe2,
    },
    {
      id: 'reports' as NavTabId,
      label: 'Audit Reports',
      icon: FileText,
    },
  ];

  const secondaryNavItems = [
    ...(user?.role === 'admin' ? [{
      id: 'admin' as NavTabId,
      label: 'Admin Control',
      icon: UserCog,
    }] : []),
    ...(user?.role === 'admin' ? [{
      id: 'settings' as NavTabId,
      label: 'Settings',
      icon: Settings,
    }] : []),
    {
      id: 'design-system' as NavTabId,
      label: 'Design System',
      icon: Palette,
      badge: 'Tokens',
      badgeType: 'brand' as const,
    },
  ];

  const handleItemClick = (id: NavTabId) => {
    onSelectTab(id);
    if (onCloseMobile) onCloseMobile();
  };

  useLayoutEffect(() => {
    const nav = navRef.current;
    if (!nav) return;

    const updateIndicator = () => {
      const activeItem = nav.querySelector<HTMLElement>('[aria-current="page"]');
      if (!activeItem) {
        setActiveIndicator((current) => ({ ...current, visible: false }));
        return;
      }

      setActiveIndicator({
        top: activeItem.offsetTop + 9,
        height: Math.max(18, activeItem.offsetHeight - 18),
        visible: true,
      });
    };

    updateIndicator();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(updateIndicator);
    observer.observe(nav);
    return () => observer.disconnect();
  }, [currentTab, user?.role]);

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {isMobileOpen && (
        <div
          className="vs-sidebar-overlay"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`vs-sidebar ${isCollapsed ? 'vs-sidebar--collapsed' : ''} ${
          isMobileOpen ? 'vs-sidebar--mobile-open' : ''
        }`}
        aria-label="Primary navigation"
      >
        {/* Brand Header */}
        <div className="vs-sidebar__brand">
          <div className="vs-sidebar__brand-link">
            <div className="vs-sidebar__brand-logo">
              <Shield size={20} />
            </div>
            {(
              <div className="vs-sidebar__brand-text">
                <div className="vs-sidebar__brand-title">
                  VulnScan
                  <span className="vs-sidebar__brand-version">v2.4</span>
                </div>
                <span className="vs-sidebar__brand-subtitle">Security Suite</span>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            {/* Desktop Collapse Button */}
            <button
              type="button"
              className="vs-sidebar__toggle-btn vs-sidebar__desktop-toggle"
              onClick={onToggleCollapse}
              title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {isCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            </button>

            {/* Mobile Close Button */}
            {onCloseMobile && (
              <button
                type="button"
                className="vs-sidebar__toggle-btn vs-sidebar__mobile-close"
                onClick={onCloseMobile}
                title="Close sidebar"
                aria-label="Close sidebar"
              >
                <X size={18} />
              </button>
            )}
          </div>
        </div>

        {/* Navigation List */}
        <nav ref={navRef} className="vs-sidebar__nav">
          <span
            className="vs-sidebar__active-indicator"
            style={{
              height: `${activeIndicator.height}px`,
              opacity: activeIndicator.visible ? 1 : 0,
              transform: `translateY(${activeIndicator.top}px)`,
            }}
            aria-hidden="true"
          />
          <div className="vs-sidebar__section-title">
            Operations
          </div>

          {mainNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`vs-sidebar__item ${isActive ? 'vs-sidebar__item--active' : ''}`}
                data-label={item.label}
                onClick={() => handleItemClick(item.id)}
                title={isCollapsed && !isMobileOpen ? item.label : undefined}
                aria-current={isActive ? 'page' : undefined}
              >
                <span className="vs-sidebar__icon">
                  <Icon size={18} />
                </span>
                {(
                  <>
                    <span className="vs-sidebar__label">{item.label}</span>
                    {item.badge && (
                      <span className={`vs-sidebar__badge vs-sidebar__badge--${item.badgeType}`}>
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </button>
            );
          })}

          <div className="vs-sidebar__section-title" style={{ marginTop: 'var(--space-4)' }}>
            Configuration
          </div>

          {secondaryNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`vs-sidebar__item ${isActive ? 'vs-sidebar__item--active' : ''}`}
                data-label={item.label}
                onClick={() => handleItemClick(item.id)}
                title={isCollapsed && !isMobileOpen ? item.label : undefined}
                aria-current={isActive ? 'page' : undefined}
              >
                <span className="vs-sidebar__icon">
                  <Icon size={18} />
                </span>
                {(
                  <>
                    <span className="vs-sidebar__label">{item.label}</span>
                    {item.badge && (
                      <span className={`vs-sidebar__badge vs-sidebar__badge--${item.badgeType}`}>
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </button>
            );
          })}
        </nav>

        <div className="vs-sidebar__footer">
          {(
            <div
              className="vs-sidebar__status-card"
              role="status"
              aria-live="polite"
              aria-atomic="true"
            >
              <div className="vs-sidebar__status-header">
                <span style={{ color: 'var(--color-text-secondary)' }}>Scan Activity</span>
                <div
                  className={`vs-sidebar__status-indicator vs-sidebar__status-indicator--${scannerStatus.toLowerCase()}`}
                >
                  <RadarPing active={shouldAnimateRadar} size="sm" />
                  <span>{scannerStatus}</span>
                </div>
              </div>
              <div className="vs-sidebar__status-detail">
                <span>{scannerDetail}</span>
              </div>
            </div>
          )}

          <div className="vs-sidebar__profile">
            <div className="vs-sidebar__profile-avatar" aria-hidden="true">
              {(user?.full_name || 'Operator').split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase()}
            </div>
            {(
              <div className="vs-sidebar__profile-copy">
                <strong>{user?.full_name || 'Operator'}</strong>
                <span>{user?.role === 'admin' ? 'Administrator' : 'Security operator'}</span>
              </div>
            )}
            <button
              type="button"
              className="vs-sidebar__logout"
              onClick={() => void logout()}
              aria-label="Log out"
              title="Log out"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
