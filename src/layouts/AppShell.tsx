import React, { useState } from 'react';
import { Sidebar, type NavTabId } from './Sidebar';
import { Header } from './Header';
import { Modal } from '../components/ui/Modal';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Play, Sparkles } from 'lucide-react';
import type { ScanType } from '../types';
import { useScans } from '../store/ScanContext';
import { useToast } from '../components/ui/Toast';
import { createDiscovery } from '../services/api';
import {
  validateCidrTarget,
  validateIpRange,
  validateSingleTarget,
  type TargetInputMode,
} from '../utils/targetValidator';
import './AppShell.css';

export interface AppShellProps {
  currentTab: NavTabId;
  onSelectTab: (tab: NavTabId) => void;
  title: string;
  subtitle?: string;
  isNewScanOpen?: boolean;
  onCloseNewScan?: () => void;
  onOpenNewScan?: () => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onSelectTab,
  title,
  subtitle,
  isNewScanOpen: controlledNewScanOpen,
  onCloseNewScan,
  onOpenNewScan,
  children,
}) => {
  const [isCollapsed, setIsCollapsed] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [internalNewScanOpen, setInternalNewScanOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const { addScan } = useScans();
  const { showToast } = useToast();

  // Controlled or uncontrolled modal state
  const isModalOpen = controlledNewScanOpen !== undefined ? controlledNewScanOpen : internalNewScanOpen;
  const setModalOpen = (open: boolean) => {
    setAuthorizationConfirmed(false);
    setTargetError(null);
    if (open) {
      if (onOpenNewScan) onOpenNewScan();
      else setInternalNewScanOpen(true);
    } else {
      if (onCloseNewScan) onCloseNewScan();
      else setInternalNewScanOpen(false);
    }
  };

  // Form states for New Scan Modal
  const [targetUrl, setTargetUrl] = useState('');
  const [targetMode, setTargetMode] = useState<TargetInputMode>('single');
  const [rangeStart, setRangeStart] = useState('');
  const [rangeEnd, setRangeEnd] = useState('');
  const [scanName, setScanName] = useState('');
  const [selectedType, setSelectedType] = useState<ScanType>('quick');
  const [isStartingScan, setIsStartingScan] = useState(false);
  const [targetError, setTargetError] = useState<string | null>(null);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);

  const scanTypes: { type: ScanType; title: string; desc: string }[] = [
    { type: 'quick', title: 'Quick Recon', desc: 'Top 100 fast TCP ports with service and version detection (-sV -T3 -F)' },
    { type: 'network', title: 'Network Discovery', desc: 'Host ping discovery sweep without port scanning (-sn)' },
    { type: 'full', title: 'Full Suite', desc: 'Comprehensive all 65,535 TCP ports with service detection (-sV -T3 -p-)' },
  ];

  const handleStartScan = async () => {
    const cleanTarget = targetUrl.trim();
    const validation = targetMode === 'single'
      ? validateSingleTarget(cleanTarget)
      : targetMode === 'cidr'
        ? validateCidrTarget(cleanTarget, 4096)
        : validateIpRange(rangeStart, rangeEnd, 4096);
    if (!validation.isValid) {
      setTargetError(validation.error || 'Enter a valid authorized target.');
      return;
    }
    if (!authorizationConfirmed) {
      setTargetError('Confirm that you own this target or have permission to test it.');
      return;
    }

    setTargetError(null);
    setIsStartingScan(true);
    try {
      if (targetMode !== 'single') {
        if (selectedType !== 'network') {
          setTargetError('CIDR subnets and IP ranges require the Network Discovery profile.');
          return;
        }
        const discovery = await createDiscovery(targetMode === 'cidr'
          ? { target_type: 'cidr', cidr: cleanTarget, authorization_mode: 'on_demand', authorization_confirmed: true }
          : {
              target_type: 'range',
              start_ip: rangeStart.trim(),
              end_ip: rangeEnd.trim(),
              authorization_mode: 'on_demand',
              authorization_confirmed: true,
            });
        setModalOpen(false);
        setTargetUrl('');
        setRangeStart('');
        setRangeEnd('');
        showToast('success', `Host discovery queued for ${discovery.target}.`);
        onSelectTab('discovery');
        return;
      }

      const finalName = scanName.trim() || `${cleanTarget} Audit`;
      await addScan({
        name: finalName,
        targetUrl: cleanTarget,
        type: selectedType,
        authorizationMode: 'on_demand',
        authorizationConfirmed: true,
      });

      setModalOpen(false);
      setTargetUrl('');
      setScanName('');
      setAuthorizationConfirmed(false);
      showToast('success', `Scan "${finalName}" initialized & dispatched.`);
      onSelectTab('scans');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to initialize scan';
      setTargetError(message);
      showToast('error', message);
    } finally {
      setIsStartingScan(false);
    }
  };

  return (
    <div className="vs-app-shell">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          onSelectTab(tab);
          setMobileMenuOpen(false);
        }}
        isCollapsed={isCollapsed}
        onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
        isMobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      {/* Main View Area */}
      <div className="vs-app-shell__main">
        <Header
          title={title}
          subtitle={subtitle}
          onOpenNewScanModal={() => setModalOpen(true)}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onToggleMobileMenu={() => setMobileMenuOpen((o) => !o)}
        />

        <main className="vs-app-shell__content">{children}</main>
      </div>

      {/* Global New Scan Launcher Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => !isStartingScan && setModalOpen(false)}
        size="md"
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sparkles size={18} color="var(--color-brand)" /> Launch Security Scan
          </span>
        }
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setModalOpen(false)}
              disabled={isStartingScan}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              leftIcon={<Play size={16} />}
              isLoading={isStartingScan}
              disabled={!authorizationConfirmed}
              onClick={handleStartScan}
            >
              Initialize & Run
            </Button>
          </>
        }
      >
        <div className="new-scan-form">
          <fieldset className="scan-target-mode">
            <legend className="vs-input-label">Target Mode</legend>
            <div className="scan-target-mode__grid">
              {([['single', 'Single IP / Hostname'], ['cidr', 'CIDR Subnet'], ['range', 'IP Range']] as const).map(([mode, label]) => (
                <button
                  type="button"
                  key={mode}
                  className={`scan-target-mode__button ${targetMode === mode ? 'scan-target-mode__button--selected' : ''}`}
                  aria-pressed={targetMode === mode}
                  onClick={() => {
                    setTargetMode(mode);
                    setTargetError(null);
                    setAuthorizationConfirmed(false);
                    if (mode !== 'single') setSelectedType('network');
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>

          {targetMode === 'range' ? (
            <div className="scan-range-inputs">
              <Input
                label="Range Start IP"
                placeholder="192.168.29.1"
                value={rangeStart}
                error={targetError || undefined}
                onChange={(event) => {
                  setRangeStart(event.target.value);
                  setTargetError(null);
                  setAuthorizationConfirmed(false);
                }}
              />
              <Input
                label="Range End IP"
                placeholder="192.168.29.254"
                value={rangeEnd}
                onChange={(event) => {
                  setRangeEnd(event.target.value);
                  setTargetError(null);
                  setAuthorizationConfirmed(false);
                }}
                helperText="The complete range must fit within one authorized CIDR scope."
              />
            </div>
          ) : (
            <Input
              label={targetMode === 'cidr' ? 'Authorized CIDR Subnet' : 'Target IP Address or Hostname'}
              placeholder={targetMode === 'cidr' ? '192.168.29.0/24' : '192.168.29.31 or host.internal'}
              value={targetUrl}
              error={targetError || undefined}
              onChange={(e) => {
                setTargetUrl(e.target.value);
                setTargetError(null);
                setAuthorizationConfirmed(false);
              }}
              helperText={targetMode === 'cidr'
                ? 'Runs one-time authenticated host discovery only after your explicit authorization confirmation.'
                : 'One IP address or hostname per on-demand scan.'}
            />
          )}

          {targetMode === 'single' && (
            <Input
              label="Scan Task Label (Optional)"
              placeholder="e.g. Q4 Staging Compliance Audit"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
            />
          )}

          <div>
            <label className="vs-input-label" style={{ display: 'block', marginBottom: '4px' }}>
              Select Scanner Engine Profile
            </label>
            <div className="scan-type-grid">
              {scanTypes.map((item) => (
                <button
                  type="button"
                  key={item.type}
                  className={`scan-type-card ${selectedType === item.type ? 'scan-type-card--selected' : ''}`}
                  onClick={() => setSelectedType(item.type)}
                  aria-pressed={selectedType === item.type}
                  disabled={targetMode !== 'single' && item.type !== 'network'}
                  title={targetMode !== 'single' && item.type !== 'network' ? 'Subnet and range targets support host discovery only.' : undefined}
                >
                  <span className="scan-type-card__title">{item.title}</span>
                  <span className="scan-type-card__desc">{item.desc}</span>
                </button>
              ))}
            </div>
            {targetMode !== 'single' && (
              <p className="scan-profile-note">CIDR and range targets use Network Discovery (-sn) only. No port scan is automatically run against discovered hosts.</p>
            )}
          </div>

          <label className="scan-authorization-confirmation">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => {
                setAuthorizationConfirmed(event.target.checked);
                setTargetError(null);
              }}
            />
            <span>
              I confirm that I own this target or have explicit permission to perform this security scan.
            </span>
          </label>
        </div>
      </Modal>
    </div>
  );
};

export default AppShell;
