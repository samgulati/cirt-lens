import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';

afterEach(() => vi.unstubAllGlobals());

describe('API failure contracts', () => {
  it('preserves the backend request ID for supportability', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: { detail: 'Approval expired', request_id: 'req-123' } }),
          {
            status: 409,
            headers: { 'content-type': 'application/json', 'x-request-id': 'req-123' },
          },
        ),
      ),
    );
    await expect(api('/approvals')).rejects.toMatchObject({
      message: 'Approval expired',
      status: 409,
      requestId: 'req-123',
    });
  });

  it('turns a network failure into an actionable operator message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    await expect(api('/health')).rejects.toThrow('CIRT Lens API is unreachable');
  });
});
