import React, { useState, useRef, useEffect } from 'react';
import {
  Bell,
  Plus,
  Search,
  ShieldCheck,
  Menu,
  LogOut,
} from 'lucide-react';
import { Button } from '../components/ui/Button';
import { useScans } from '../store/ScanContext';
import { isActiveScanStatus } from '../utils/scanActivity';
import './Header.css';
import { useAuth } from '../components/auth/authContext';

export interface HeaderProps {
  title: string;
  subtitle?: string;
  onOpenNewScanModal: () => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onToggleMobileMenu?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  onOpenNewScanModal,
  searchQuery,
  onSearchChange,
  onToggleMobileMenu,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { scans, isLoading: scansLoading, isStale: scansStale, error: scansError } = useScans();
  const { user, logout } = useAuth();
  const activeScanCount = scans.filter((scan) => isActiveScanStatus(scan.status)).length;
  const engineStatus = scansLoading
    ? 'Syncing engine telemetry'
    : scansError && scans.length === 0
      ? 'Engine telemetry unavailable'
      : scansStale
        ? 'Engine telemetry stale'
        : activeScanCount > 0
          ? `${activeScanCount} engine${activeScanCount === 1 ? '' : 's'} active`
          : 'Engines idle';

  // Close notifications on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    };
    if (showNotifications) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showNotifications]);

  return (
    <header className="vs-header">
      {/* Page Title & Breadcrumbs */}
      <div className="vs-header__left">
        {onToggleMobileMenu && (
          <button
            type="button"
            className="vs-header__mobile-menu-btn"
            onClick={onToggleMobileMenu}
            aria-label="Open navigation menu"
          >
            <Menu size={18} />
          </button>
        )}
        <h1 className="vs-header__title">{title}</h1>
        {subtitle && <span className="vs-header__badge">{subtitle}</span>}
      </div>

      {/* Global Search Bar */}
      <div className="vs-header__center">
        <div className="vs-header__search">
          <div className="vs-header__search-icon" aria-hidden="true">
            <Search size={16} />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search CVEs, endpoints, scan runs..."
          />
          <kbd className="vs-header__search-kbd">Ctrl K</kbd>
        </div>
      </div>

      {/* Right Actions */}
      <div className="vs-header__right" ref={dropdownRef}>
        <div className="vs-header__engine-status">
          <ShieldCheck size={16} color="var(--color-low)" />
          <span role="status" aria-live="polite">
            {engineStatus}
          </span>
        </div>

        {/* Notifications Button */}
        <button
          type="button"
          className="vs-header__action-btn"
          onClick={() => setShowNotifications(!showNotifications)}
          aria-label="View notifications"
          aria-expanded={showNotifications}
          aria-controls="security-events-popover"
        >
          <Bell size={18} />
          <span className="vs-header__notif-badge" aria-hidden="true" />
        </button>

        {/* Notifications Popover */}
        {showNotifications && (
          <div id="security-events-popover" className="vs-header__notif-dropdown" role="status" aria-live="polite">
            <div className="vs-notif-header">
              <span className="vs-notif-title">Recent Security Events</span>
              <span className="vs-notif-empty-count">0 available</span>
            </div>
            <div className="vs-notif-list">
              <p className="vs-notif-empty">
                No notification feed is available from the backend.
              </p>
            </div>
          </div>
        )}

        <Button
          variant="primary"
          size="sm"
          leftIcon={<Plus size={16} />}
          onClick={onOpenNewScanModal}
        >
          New Scan
        </Button>

        <div className="vs-header__divider" />

        {/* User Profile */}
        <div className="vs-header__user">
          <div className="vs-header__avatar">{(user?.full_name || 'Operator').split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase()}</div>
          <div className="vs-header__user-info">
            <span className="vs-header__user-name">{user?.full_name || 'Operator'}</span>
            <span className="vs-header__user-role">{user?.role === 'admin' ? 'Platform Administrator' : 'Security Operator'}</span>
          </div>
        </div>
        <button type="button" className="vs-header__action-btn" aria-label="Log out" title="Log out" onClick={() => void logout()}><LogOut size={17} /></button>
      </div>
    </header>
  );
};

export default Header;
