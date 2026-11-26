import { lazy, Suspense, useEffect, useState } from 'react';
import { AppShell } from './layouts/AppShell';
import type { NavTabId } from './layouts/Sidebar';
import { ScanProvider } from './store/ScanContext';
import { ToastProvider } from './components/ui/Toast';
import { ErrorBoundary } from './components/ui/ErrorBoundary';
import { AuthGate } from './components/auth/AuthGate';
import { useAuth } from './components/auth/authContext';
import { RoleGuard } from './components/auth/RoleGuard';
import './App.css';

// Keep tab-specific code out of the authenticated shell until it is needed.
// The dashboard and reports also depend on substantial chart/PDF code, so this
// prevents those assets from inflating the initial application chunk.
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })));
const ScansPage = lazy(() => import('./pages/ScansPage').then((module) => ({ default: module.ScansPage })));
const DiscoveryPage = lazy(() => import('./pages/DiscoveryPage').then((module) => ({ default: module.DiscoveryPage })));
const VulnerabilitiesPage = lazy(() => import('./pages/VulnerabilitiesPage').then((module) => ({ default: module.VulnerabilitiesPage })));
const AssetsPage = lazy(() => import('./pages/AssetsPage').then((module) => ({ default: module.AssetsPage })));
const ReportsPage = lazy(() => import('./pages/ReportsPage').then((module) => ({ default: module.ReportsPage })));
const ScanReportPage = lazy(() => import('./pages/ScanReportPage').then((module) => ({ default: module.ScanReportPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((module) => ({ default: module.SettingsPage })));
const AdminPage = lazy(() => import('./pages/AdminPage').then((module) => ({ default: module.AdminPage })));
const DesignSystemShowcase = lazy(() => import('./pages/DesignSystemShowcase').then((module) => ({ default: module.DesignSystemShowcase })));

function PageLoading() {
  return (
    <div className="vs-page-loading" role="status" aria-live="polite">
      Loading workspace view…
    </div>
  );
}

function AppContent() {
  const { user } = useAuth();
  const tabFromPath = (): NavTabId => {
    const first = window.location.pathname.split('/').filter(Boolean)[0];
    if (first === 'scans') return 'scans';
    if (first === 'discovery') return 'discovery';
    if (first === 'vulnerabilities') return 'vulnerabilities';
    if (first === 'assets' || first === 'targets') return 'targets';
    if (first === 'reports') return 'reports';
    if (first === 'settings') return 'settings';
    if (first === 'admin') return 'admin';
    return 'dashboard';
  };
  const [currentTab, setCurrentTab] = useState<NavTabId>(tabFromPath);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);
  const readReportScanId = () => {
    const match = window.location.pathname.match(/^\/reports\/([^/]+)\/?$/);
    return match ? decodeURIComponent(match[1]) : null;
  };
  const [reportScanId, setReportScanId] = useState<string | null>(readReportScanId);

  useEffect(() => {
    const handlePopState = () => {
      setReportScanId(readReportScanId());
      setCurrentTab(tabFromPath());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const openScanReport = (scanId: string) => {
    window.history.pushState({}, '', `/reports/${encodeURIComponent(scanId)}`);
    setReportScanId(scanId);
  };
  const closeScanReport = () => {
    window.history.pushState({}, '', '/');
    setReportScanId(null);
    setCurrentTab('scans');
  };
  const selectTab = (tab: NavTabId) => {
    const paths: Partial<Record<NavTabId, string>> = { dashboard: '/', scans: '/scans', discovery: '/discovery', vulnerabilities: '/vulnerabilities', targets: '/assets', reports: '/reports', settings: '/settings', admin: '/admin', 'design-system': '/design-system' };
    window.history.pushState({}, '', paths[tab] || '/');
    setReportScanId(null);
    setCurrentTab(tab);
  };

  const getPageMeta = (tab: NavTabId): { title: string; subtitle?: string } => {
    switch (tab) {
      case 'dashboard':
        return { title: 'Security Dashboard', subtitle: 'Live Telemetry & Posture' };
      case 'scans':
        return { title: 'Scan Engine Management', subtitle: 'Live Orchestration' };
      case 'discovery':
        return { title: 'Network Discovery', subtitle: 'Authorized Host Inventory' };
      case 'vulnerabilities':
        return { title: 'Vulnerabilities & CVEs', subtitle: 'Triage & Remediation' };
      case 'targets':
        return { title: 'Asset Management', subtitle: 'Infrastructure & Cloud' };
      case 'reports':
        return { title: 'Security Reports', subtitle: 'PDF / CSV Export' };
      case 'settings':
        return { title: 'Platform Settings', subtitle: 'Configuration & Keys' };
      case 'admin':
        return { title: 'Admin Control Center', subtitle: 'Users, Sessions, Evidence & Audit' };
      case 'design-system':
        return { title: 'Design System Showcase', subtitle: 'SOC Theme Tokens' };
      default:
        return { title: 'VulnScan Suite' };
    }
  };

  const isDeniedAdminRoute = (currentTab === 'admin' || currentTab === 'settings') && user?.role !== 'admin';
  const meta = isDeniedAdminRoute
    ? { title: 'Access denied', subtitle: 'Administrator access required' }
    : reportScanId
    ? { title: 'Scan Report', subtitle: 'Persisted Evidence & Findings' }
    : getPageMeta(currentTab);

  return (
    <AppShell
      currentTab={reportScanId ? 'reports' : currentTab}
      onSelectTab={selectTab}
      title={meta.title}
      subtitle={meta.subtitle}
      isNewScanOpen={isNewScanOpen}
      onCloseNewScan={() => setIsNewScanOpen(false)}
      onOpenNewScan={() => setIsNewScanOpen(true)}
    >
      <Suspense fallback={<PageLoading />}>
        {reportScanId ? (
          <ScanReportPage scanId={reportScanId} onBack={closeScanReport} />
        ) : currentTab === 'dashboard' ? (
          <DashboardPage
            onNavigateToScans={() => setCurrentTab('scans')}
            onOpenNewScan={() => setIsNewScanOpen(true)}
          />
        ) : currentTab === 'scans' ? (
          <ScansPage onOpenNewScanModal={() => setIsNewScanOpen(true)} onViewReport={openScanReport} />
        ) : currentTab === 'discovery' ? (
          <DiscoveryPage />
        ) : currentTab === 'vulnerabilities' ? <VulnerabilitiesPage />
          : currentTab === 'targets' ? <AssetsPage />
            : currentTab === 'reports' ? <ReportsPage />
              : currentTab === 'settings' ? <RoleGuard requiredRole="admin"><SettingsPage /></RoleGuard>
                : currentTab === 'admin' ? <RoleGuard requiredRole="admin"><AdminPage /></RoleGuard>
                : <DesignSystemShowcase />}
      </Suspense>
    </AppShell>
  );
}

export function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <AuthGate>
          <ScanProvider>
            <AppContent />
          </ScanProvider>
        </AuthGate>
      </ToastProvider>
    </ErrorBoundary>
  );
}

export default App;
