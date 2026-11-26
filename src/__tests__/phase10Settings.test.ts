import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  getSettings,
  removeIntegrationSecret,
  removePlatformApiKey,
  replacePlatformApiKey,
  saveIntegrationSecret,
  updateSettings,
} from '../services/api';
import type { PlatformSettings } from '../types';
import { generatePlatformApiKey } from '../utils/apiKey';

const settingsResponse: PlatformSettings = {
  preferences: {
    max_concurrent_scans: 3,
    scanner_rate_limit_per_minute: 100,
    session_timeout_minutes: 30,
    accent_color: '#3b82f6',
  },
  integrations: {
    jira: { configured: false, masked_hint: null, updated_at: null },
    slack: { configured: true, masked_hint: 'http••••alue', updated_at: '2026-10-28T00:00:00Z' },
    splunk: { configured: false, masked_hint: null, updated_at: null },
  },
  api_key: { configured: true, masked_hint: 'vsec••••A1A1', updated_at: '2026-10-28T00:00:00Z' },
  runtime: {
    environment: 'test',
    app_version: '1.0.0',
    nmap_available: false,
    runtime_max_concurrent_scans: 3,
    runtime_rate_limit_per_minute: 100,
    concurrency_restart_required: false,
    rate_limit_enforced: true,
    session_enforcement_available: true,
    api_key_authentication_available: true,
    integration_encryption_configured: true,
  },
};

afterEach(() => vi.unstubAllGlobals());

describe('Phase 10 settings API integration', () => {
  it('generates high-entropy one-time platform API keys', () => {
    const first = generatePlatformApiKey();
    const second = generatePlatformApiKey();
    expect(first).toMatch(/^vsec_live_[0-9a-f]{64}$/);
    expect(second).not.toBe(first);
  });
  it('loads masked settings without raw credentials', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(settingsResponse), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));
    const result = await getSettings();
    expect(result.integrations.slack.masked_hint).toBe('http••••alue');
    expect(JSON.stringify(result)).not.toContain('secret-value');
  });

  it('submits validated preferences through PATCH', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(settingsResponse), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    await updateSettings(settingsResponse.preferences);
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/settings'), expect.objectContaining({ method: 'PATCH' }));
  });

  it('submits write-only credentials and receives metadata only', async () => {
    const metadata = { configured: true, masked_hint: 'jira••••alue', updated_at: '2026-10-28T00:00:00Z' };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(metadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const rawSecret = 'jira-super-secret-value';
    const result = await saveIntegrationSecret('jira', rawSecret);
    expect(result).toEqual(metadata);
    expect(JSON.stringify(result)).not.toContain(rawSecret);
    expect(fetchMock.mock.calls[0][1]?.body).toContain(rawSecret);
  });

  it('submits a generated API key without expecting it back', async () => {
    const metadata = { configured: true, masked_hint: 'vsec••••A1A1', updated_at: '2026-10-28T00:00:00Z' };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(metadata), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));
    const rawKey = `vsec_live_${'A1'.repeat(32)}`;
    const result = await replacePlatformApiKey(rawKey);
    expect(JSON.stringify(result)).not.toContain(rawKey);
  });

  it('surfaces validation and network errors instead of false success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'Invalid credential' }), {
      status: 422,
      statusText: 'Unprocessable Entity',
      headers: { 'Content-Type': 'application/json' },
    })));
    await expect(saveIntegrationSecret('jira', 'bad')).rejects.toMatchObject({ status: 422 });

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('network down')));
    await expect(getSettings()).rejects.toBeInstanceOf(ApiError);
    await expect(removeIntegrationSecret('jira')).rejects.toBeInstanceOf(ApiError);
  });

  it('deletes stored credentials only after backend 204 confirmation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(removeIntegrationSecret('slack')).resolves.toBeUndefined();
    await expect(removePlatformApiKey()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('/settings/integrations/slack'),
      expect.objectContaining({ method: 'DELETE', credentials: 'include' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/settings/api-key'),
      expect.objectContaining({ method: 'DELETE', credentials: 'include' }),
    );
  });
});
