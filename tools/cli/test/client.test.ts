import { afterEach, describe, expect, it } from 'vitest';
import { createClient } from '../src/client.js';

const PID = 'prj_0123456789ab';
const saved = Object.getOwnPropertyDescriptor(URLSearchParams.prototype, 'size');
afterEach(() => {
  if (saved) Object.defineProperty(URLSearchParams.prototype, 'size', saved);
});

describe('query string without URLSearchParams.size (Node < 18.16)', () => {
  it('builds the URL from toString()', async () => {
    Object.defineProperty(URLSearchParams.prototype, 'size', { configurable: true, get: () => undefined });
    const urls: string[] = [];
    const f = (async (u: string | URL) => (urls.push(String(u)), new Response('{"ok":true}'))) as typeof fetch;
    const c = createClient({ apiUrl: 'https://x.test/', key: 'mk_k', fetch: f });
    await c.searchEvents(PID, { limit: 3 });
    await c.searchEvents(PID);
    expect(urls).toEqual([
      `https://x.test/v1/management/projects/${PID}/events?limit=3`,
      `https://x.test/v1/management/projects/${PID}/events`,
    ]);
  });
});
