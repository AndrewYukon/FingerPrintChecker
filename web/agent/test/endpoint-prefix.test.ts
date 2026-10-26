import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

// Runs the REAL vendored agent and records the URLs it requests.
async function requestedUrls(endpoint: string): Promise<string[]> {
  const urls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: unknown) => {
      urls.push(typeof input === 'string' ? input : String((input as { url?: string }).url ?? input));
      const u = urls[urls.length - 1];
      const body = u.includes('/v2/challenge')
        ? { ok: true, protocolVersion: 2, challenge: 'ch_test', expiresIn: 60 }
        : { ok: false, reason: 'bad_request' };
      return new Response(JSON.stringify(body), {
        status: u.includes('/v2/challenge') ? 200 : 400,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  delete (window as { FpGuardAgent?: unknown }).FpGuardAgent;
  const el = document.createElement('script');
  el.textContent = readFileSync(resolve(__dirname, '../vendor/fp-agent.min.js'), 'utf8');
  document.head.appendChild(el);
  const g = (window as unknown as { FpGuardAgent: { identifyV2: (o: object) => Promise<unknown> } }).FpGuardAgent;
  await g
    .identifyV2({ baseUrl: endpoint, publishableKey: 'pk_test', intentToken: 'it_x' })
    .catch(() => undefined);
  return urls;
}

beforeEach(() => vi.useRealTimers());
afterEach(() => vi.unstubAllGlobals());

for (const endpoint of ['https://x.com/fpc', 'https://x.com/fpc/']) {
  it(`endpoint ${endpoint} keeps the path prefix`, async () => {
    const urls = await requestedUrls(endpoint);
    expect(urls.length).toBeGreaterThan(0);
    for (const u of urls) expect(u.startsWith('https://x.com/fpc/v2/')).toBe(true);
    expect(urls.some((u) => u.startsWith('https://x.com/fpc/v2/challenge'))).toBe(true);
    expect(urls.some((u) => u === 'https://x.com/fpc/v2/identify')).toBe(true);
  });
}
