import React, { useEffect, useState } from 'react';
import { Database, Key, Palette, Save, ServerCog, ShieldCheck, Trash2, Webhook } from 'lucide-react';
import { AuthorizedTargetsManager } from '../components/targets/AuthorizedTargetsManager';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { StateView } from '../components/ui/StateView';
import { useToast } from '../components/ui/Toast';
import { useAsync } from '../hooks/useAsync';
import {
  getSettings,
  endAuthSession,
  removeIntegrationSecret,
  removePlatformApiKey,
  replacePlatformApiKey,
  saveIntegrationSecret,
  updateSettings,
} from '../services/api';
import type { IntegrationProvider, PlatformPreferences, PlatformSettings } from '../types';
import { generatePlatformApiKey } from '../utils/apiKey';
import './SettingsPage.css';

type SettingsTab = 'scanner' | 'authorized-targets' | 'integrations' | 'security' | 'appearance' | 'system';

const TABS: { key: SettingsTab; label: string; icon: React.ElementType }[] = [
  { key: 'scanner', label: 'Scanner', icon: Database },
  { key: 'authorized-targets', label: 'Authorized Targets', icon: ShieldCheck },
  { key: 'integrations', label: 'Integrations', icon: Webhook },
  { key: 'security', label: 'API & Security', icon: Key },
  { key: 'appearance', label: 'Appearance', icon: Palette },
  { key: 'system', label: 'System', icon: ServerCog },
];

const INTEGRATIONS: { provider: IntegrationProvider; name: string; description: string; placeholder: string }[] = [
  { provider: 'jira', name: 'Jira API token', description: 'Stored credential for the Jira integration.', placeholder: 'Paste Jira API token' },
  { provider: 'slack', name: 'Slack webhook', description: 'Stored incoming-webhook URL for Slack alerts.', placeholder: 'https://hooks.slack.com/services/…' },
  { provider: 'splunk', name: 'Splunk token', description: 'Stored token for the Splunk SIEM integration.', placeholder: 'Paste Splunk token' },
];

const SettingRow: React.FC<{ label: string; description?: string; children: React.ReactNode }> = ({ label, description, children }) => (
  <div className="vs-settings-row">
    <div className="vs-settings-row__label">
      <div className="vs-settings-row__title">{label}</div>
      {description && <div className="vs-settings-row__description">{description}</div>}
    </div>
    <div className="vs-settings-row__control">{children}</div>
  </div>
);

const SectionTitle: React.FC<{ title: string; subtitle: string }> = ({ title, subtitle }) => (
  <div className="vs-settings-section-title">
    <h3>{title}</h3>
    <p>{subtitle}</p>
  </div>
);

const SettingsEditor: React.FC<{ initialSettings: PlatformSettings }> = ({ initialSettings }) => {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<SettingsTab>('scanner');
  const [settings, setSettings] = useState<PlatformSettings>(initialSettings);
  const [preferences, setPreferences] = useState<PlatformPreferences>(initialSettings.preferences);
  const [secrets, setSecrets] = useState<Record<IntegrationProvider, string>>({ jira: '', slack: '', splunk: '' });
  const [apiKey, setApiKey] = useState('');
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<IntegrationProvider | 'api-key' | null>(null);

  useEffect(() => {
    document.documentElement.style.setProperty('--color-brand', preferences.accent_color);
  }, [preferences.accent_color]);

  const savePreferences = async () => {
    setBusyAction('preferences');
    try {
      const saved = await updateSettings(preferences);
      setSettings(saved);
      setPreferences(saved.preferences);
      document.documentElement.style.setProperty('--color-brand', saved.preferences.accent_color);
      showToast('success', 'Platform preferences saved.');
    } catch (requestError) {
      showToast('error', requestError instanceof Error ? requestError.message : 'Unable to save preferences.');
    } finally {
      setBusyAction(null);
    }
  };

  const saveSecret = async (provider: IntegrationProvider) => {
    const secret = secrets[provider];
    if (!secret.trim()) {
      showToast('error', 'Enter a credential before saving.');
      return;
    }
    setBusyAction(provider);
    try {
      const saved = await saveIntegrationSecret(provider, secret);
      setSettings((current) => ({ ...current, integrations: { ...current.integrations, [provider]: saved } }));
      setSecrets((current) => ({ ...current, [provider]: '' }));
      showToast('success', `${provider.toUpperCase()} credential saved.`);
    } catch (requestError) {
      showToast('error', requestError instanceof Error ? requestError.message : 'Unable to save credential.');
    } finally {
      setBusyAction(null);
    }
  };

  const saveApiKey = async () => {
    if (!apiKey) return;
    setBusyAction('api-key');
    try {
      const saved = await replacePlatformApiKey(apiKey);
      setSettings((current) => ({ ...current, api_key: saved }));
      setApiKey('');
      showToast('success', 'Platform API key verifier replaced.');
      window.dispatchEvent(new Event('vulnscanner:authentication-required'));
    } catch (requestError) {
      showToast('error', requestError instanceof Error ? requestError.message : 'Unable to replace API key.');
    } finally {
      setBusyAction(null);
    }
  };

  const endCurrentSession = async () => {
    setBusyAction('end-session');
    try {
      await endAuthSession();
      window.dispatchEvent(new Event('vulnscanner:authentication-required'));
    } catch (requestError) {
      showToast('error', requestError instanceof Error ? requestError.message : 'Unable to end the session.');
    } finally {
      setBusyAction(null);
    }
  };

  const removeSecret = async () => {
    if (!confirmRemove) return;
    const target = confirmRemove;
    setBusyAction(`remove-${target}`);
    try {
      if (target === 'api-key') {
        await removePlatformApiKey();
        setSettings((current) => ({ ...current, api_key: { configured: false, masked_hint: null, updated_at: null } }));
      } else {
        await removeIntegrationSecret(target);
        setSettings((current) => ({
          ...current,
          integrations: { ...current.integrations, [target]: { configured: false, masked_hint: null, updated_at: null } },
        }));
      }
      setConfirmRemove(null);
      showToast('success', 'Stored credential removed.');
      if (target === 'api-key') {
        window.dispatchEvent(new Event('vulnscanner:authentication-required'));
      }
    } catch (requestError) {
      showToast('error', requestError instanceof Error ? requestError.message : 'Unable to remove credential.');
    } finally {
      setBusyAction(null);
    }
  };

  const renderTab = () => {
    if (activeTab === 'authorized-targets') return <AuthorizedTargetsManager />;

    if (activeTab === 'scanner') return (
      <>
        <SectionTitle title="Scanner Configuration" subtitle="Database-managed limits applied to real Nmap scan dispatches." />
        <SettingRow label="Maximum concurrent scans" description={`Current runtime limit: ${settings.runtime.runtime_max_concurrent_scans}`}>
          <Input type="number" min={1} max={32} value={preferences.max_concurrent_scans} onChange={(event) => setPreferences({ ...preferences, max_concurrent_scans: Number(event.target.value) })} />
        </SettingRow>
        <SettingRow label="Rate limit" description={`Enforced rolling dispatch limit. Current runtime: ${settings.runtime.runtime_rate_limit_per_minute} scans/minute.`}>
          <Input type="number" min={1} max={10000} value={preferences.scanner_rate_limit_per_minute} onChange={(event) => setPreferences({ ...preferences, scanner_rate_limit_per_minute: Number(event.target.value) })} />
        </SettingRow>
        {settings.runtime.concurrency_restart_required && <div className="vs-settings-notice vs-settings-notice--warning">Existing scans are still using the previous concurrency limit. The saved limit applies when the active queue drains.</div>}
      </>
    );

    if (activeTab === 'integrations') return (
      <>
        <SectionTitle title="Integration Credentials" subtitle="Only Jira, Slack, and Splunk from the original specification are supported. Values are write-only after submission." />
        {!settings.runtime.integration_encryption_configured && <div className="vs-settings-notice vs-settings-notice--warning">Saving is disabled until <code>INTEGRATION_ENCRYPTION_KEY</code> is configured on the API server.</div>}
        {INTEGRATIONS.map(({ provider, name, description, placeholder }) => {
          const statusValue = settings.integrations[provider];
          return <SettingRow key={provider} label={name} description={statusValue.configured ? `Credential stored as ${statusValue.masked_hint}. Connection not tested.` : description}>
            <div className="vs-settings-secret-control">
              <Input type="password" autoComplete="new-password" placeholder={placeholder} value={secrets[provider]} onChange={(event) => setSecrets({ ...secrets, [provider]: event.target.value })} />
              <Button size="sm" variant="outline" isLoading={busyAction === provider} disabled={!settings.runtime.integration_encryption_configured} onClick={() => saveSecret(provider)}>{statusValue.configured ? 'Replace' : 'Save'}</Button>
              {statusValue.configured && <Button size="sm" variant="ghost" aria-label={`Remove ${provider} credential`} onClick={() => setConfirmRemove(provider)}><Trash2 size={14} /></Button>}
            </div>
          </SettingRow>;
        })}
      </>
    );

    if (activeTab === 'security') return (
      <>
        <SectionTitle title="API Key & Session Security" subtitle="API keys authenticate scripts directly and are exchanged for HttpOnly browser sessions. Only one-way verifiers are stored." />
        <SettingRow label="Session timeout" description="Server-enforced sliding inactivity timeout for the current operator session.">
          <select value={preferences.session_timeout_minutes} onChange={(event) => setPreferences({ ...preferences, session_timeout_minutes: Number(event.target.value) })}>
            {[15, 30, 60, 240, 1440].map((minutes) => <option key={minutes} value={minutes}>{minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hour${minutes === 60 ? '' : 's'}`}</option>)}
          </select>
        </SettingRow>
        <SettingRow label="Platform API key" description={settings.api_key.configured ? `Configured as ${settings.api_key.masked_hint}` : 'No API key verifier is configured.'}>
          <div className="vs-settings-secret-control">
            <Input type="text" readOnly autoComplete="off" placeholder="Generate a new key" value={apiKey} />
            <Button size="sm" variant="outline" onClick={() => setApiKey(generatePlatformApiKey())}>Generate</Button>
            <Button size="sm" isLoading={busyAction === 'api-key'} disabled={!apiKey} onClick={saveApiKey}>Save</Button>
            {settings.api_key.configured && <Button size="sm" variant="ghost" aria-label="Remove platform API key" onClick={() => setConfirmRemove('api-key')}><Trash2 size={14} /></Button>}
          </div>
        </SettingRow>
        {apiKey && <div className="vs-settings-notice">Copy the generated key before saving. The server will never return it, and this field clears after success.</div>}
        <SettingRow label="Current browser session" description="Immediately revoke this server-tracked session and return to the authentication gate.">
          <Button variant="outline" size="sm" isLoading={busyAction === 'end-session'} onClick={endCurrentSession}>End Session</Button>
        </SettingRow>
      </>
    );

    if (activeTab === 'appearance') return (
      <>
        <SectionTitle title="Appearance" subtitle="Choose the persisted accent color used by primary controls." />
        <SettingRow label="Accent color" description="Six-digit hexadecimal color.">
          <div className="vs-settings-color-control"><input type="color" value={preferences.accent_color} onChange={(event) => setPreferences({ ...preferences, accent_color: event.target.value })} /><code>{preferences.accent_color}</code></div>
        </SettingRow>
      </>
    );

    return (
      <>
        <SectionTitle title="Application Information" subtitle="Observed server configuration and capabilities. No connection checks are simulated." />
        <div className="vs-settings-status-grid">
          <div><span>API version</span><strong>{settings.runtime.app_version}</strong></div>
          <div><span>Environment</span><strong>{settings.runtime.environment}</strong></div>
          <div><span>Nmap</span><strong>{settings.runtime.nmap_available ? 'Available' : 'Unavailable'}</strong></div>
          <div><span>Secret encryption</span><strong>{settings.runtime.integration_encryption_configured ? 'Configured' : 'Not configured'}</strong></div>
          <div><span>Session enforcement</span><strong>{settings.runtime.session_enforcement_available ? 'Available' : 'Unavailable'}</strong></div>
          <div><span>API-key authentication</span><strong>{settings.runtime.api_key_authentication_available ? 'Available' : 'Unavailable'}</strong></div>
        </div>
      </>
    );
  };

  return (
    <>
      <div className="vs-settings-layout">
        <div className="vs-settings-tabs" role="tablist">
          {TABS.map(({ key, label, icon: Icon }) => <button key={key} type="button" role="tab" aria-selected={activeTab === key} onClick={() => setActiveTab(key)} className={`vs-settings-tab-btn ${activeTab === key ? 'vs-settings-tab-btn--active' : ''}`}><Icon size={15} />{label}</button>)}
        </div>
        <div className="vs-settings-panel">
          {renderTab()}
          {activeTab !== 'integrations' && activeTab !== 'authorized-targets' && activeTab !== 'system' && <div className="vs-settings-actions"><Button leftIcon={<Save size={14} />} isLoading={busyAction === 'preferences'} onClick={savePreferences}>Save Changes</Button></div>}
        </div>
      </div>
      <Modal isOpen={confirmRemove !== null} onClose={() => !busyAction?.startsWith('remove-') && setConfirmRemove(null)} size="sm" title="Remove stored credential" footer={<><Button variant="ghost" disabled={busyAction?.startsWith('remove-')} onClick={() => setConfirmRemove(null)}>Cancel</Button><Button variant="danger" isLoading={busyAction?.startsWith('remove-')} onClick={removeSecret}>Remove</Button></>}><p className="vs-settings-modal-copy">This removes the stored verifier or encrypted credential. The action cannot be undone.</p></Modal>
    </>
  );
};

export const SettingsPage: React.FC = () => {
  const { data, state, error, refetch, isRefreshing, isStale, lastUpdated } = useAsync(getSettings);

  return (
    <div className="vs-settings-container animate-fade-in">
      <div className="vs-settings-heading"><h2>Settings</h2><p>Manage scanner preferences, approved integrations, and platform credentials.</p></div>
      <StateView state={state} error={error} onRetry={refetch} isRefreshing={isRefreshing} isStale={isStale} staleError={error} lastUpdated={lastUpdated} loadingMessage="Loading platform settings…">
        {data && <SettingsEditor key={JSON.stringify(data)} initialSettings={data} />}
      </StateView>
    </div>
  );
};

export default SettingsPage;
