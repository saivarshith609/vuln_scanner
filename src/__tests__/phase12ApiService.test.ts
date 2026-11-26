import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, deleteScan, getAssets, getScans } from '../services/api';

afterEach(() => vi.unstubAllGlobals());

describe('Phase 12: API service boundary', () => {
  it('preserves FastAPI validation messages without exposing response internals', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      detail: [{ msg: 'target: field required' }, { msg: 'scan_type: invalid value' }],
    }), {
      status: 422,
      statusText: 'Unprocessable Entity',
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(getAssets()).rejects.toMatchObject({
      name: 'ApiError',
      status: 422,
      message: 'target: field required; scan_type: invalid value',
    });
  });

  it('handles 204 responses without attempting JSON parsing', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(deleteScan('scan-204')).resolves.toEqual({ success: true });
  });

  it('encodes scan query parameters and preserves typed backend mapping', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [{
        id: 'scan-query',
        target: 'host.example',
        scan_type: 'quick',
        status: 'failed',
        progress: 40,
        error_message: 'scanner stopped',
        created_at: '2026-10-28T00:00:00Z',
      }],
      total: 1,
      page: 1,
      size: 100,
      pages: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);

    const scans = await getScans({ target: 'host example&prod', status: 'failed' });
    expect(scans[0].status).toBe('failed');
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain('target=host%20example%26prod');
    expect(url).toContain('status=failed');
  });

  it('propagates request cancellation without converting it to a fake response', async () => {
    const controller = new AbortController();
    vi.stubGlobal('fetch', vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      })));

    const pending = getAssets(controller.signal);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('does not expose raw API-key material in request URLs', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      items: [], total: 0, page: 1, size: 100, pages: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);

    await getScans({ target: 'authorized-host' });
    expect(String(fetchMock.mock.calls[0][0])).not.toContain('vsec_live_');
  });

  it('uses ApiError for invalid JSON instead of leaking parser details', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('not-json', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(getAssets()).rejects.toMatchObject({
      name: 'ApiError',
      status: 200,
      message: 'The API returned an invalid JSON response.',
    } satisfies Partial<ApiError>);
  });
});
