import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FpChecker, FpCheckerApiError } from '../src/index.js';

const spec = JSON.parse(
  readFileSync(new URL('../../../openapi/fpchecker-api.json', import.meta.url), 'utf8'),
);

type Call = { url: string; init: RequestInit };
function fakeFetch(responses: Array<Response | Error>) {
  const calls: Call[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const r = responses.shift();
    if (!r) throw new Error('no more responses');
    if (r instanceof Error) throw r;
    return r;
  }) as typeof fetch;
  return { f, calls };
}
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
const mk = (responses: Array<Response | Error>, extra = {}) => {
  const { f, calls } = fakeFetch(responses);
  const sleeps: number[] = [];
  const client = new FpChecker({
    secretKey: 'sk_test_123',
    fetch: f,
    sleep: async (ms: number) => void sleeps.push(ms),
    ...extra,
  });
  return { client, calls, sleeps };
};

describe('client surface', () => {
  it('every operationId in openapi has a client method', () => {
    const { client } = mk([]);
    const ids: string[] = [];
    for (const item of Object.values<Record<string, { operationId?: string }>>(spec.paths))
      for (const op of Object.values(item)) if (op && op.operationId) ids.push(op.operationId);
    expect(ids.length).toBeGreaterThanOrEqual(17);
    const missing = ids.filter((id) => typeof (client as never)[id] !== 'function');
    expect(missing).toEqual([]);
  });

  it('requires a secret key', () => {
    expect(() => new FpChecker({ secretKey: '' })).toThrow();
  });
});

describe('requests', () => {
  it('sends sk_ in X-Secret-Key and never in the URL', async () => {
    const { client, calls } = mk([json(200, { ok: true })]);
    await client.getEvent('evt_1');
    const call = calls[0]!;
    expect(call.url).toBe('https://api.fpchecker.com/v1/events/evt_1');
    expect(call.url).not.toContain('sk_');
    expect((call.init.headers as Record<string, string>)['X-Secret-Key']).toBe('sk_test_123');
  });

  it('builds query strings, skips undefined, encodes path params, honours baseUrl', async () => {
    const { client, calls } = mk([json(200, { ok: true })], { baseUrl: 'https://x.test/' });
    await client.searchEvents({ visitorId: 'v 1', bot: true, limit: 5, linkedId: undefined });
    expect(calls[0]!.url).toBe('https://x.test/v1/events?visitorId=v+1&bot=true&limit=5');
    const m = mk([json(200, {})]);
    await m.client.getVisitor('a/b');
    expect(m.calls[0]!.url).toBe('https://api.fpchecker.com/v1/visitors/a%2Fb');
  });

  it('POST sends JSON body', async () => {
    const { client, calls } = mk([json(200, { ok: true })]);
    await client.checkEligibility({ visitorId: 'v_1' });
    const c = calls[0]!;
    expect(c.init.method).toBe('POST');
    expect(c.init.body).toBe('{"visitorId":"v_1"}');
    expect((c.init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });

  it('returns 2xx ok:false bodies as data', async () => {
    const { client } = mk([json(200, { ok: false, reason: 'quota_exhausted' })]);
    await expect(client.checkQuota({})).resolves.toEqual({ ok: false, reason: 'quota_exhausted' });
  });
});

describe('errors', () => {
  it('non-2xx -> FpCheckerApiError with code from error', async () => {
    const { client } = mk([json(403, { ok: false, error: 'forbidden' })]);
    const e = await client.getEvent('e').catch((x) => x);
    expect(e).toBeInstanceOf(FpCheckerApiError);
    expect(e.status).toBe(403);
    expect(e.code).toBe('forbidden');
    expect(e.retryAfter).toBeNull();
  });

  it('code falls back to reason, then null for non-JSON', async () => {
    const a = mk([json(400, { ok: false, reason: 'bad_input' })]);
    expect((await a.client.updateEvent('e', {}).catch((x) => x)).code).toBe('bad_input');
    const b = mk([new Response('<html>', { status: 502 })]);
    const e = await b.client.createIntent({}).catch((x) => x);
    expect(e).toBeInstanceOf(FpCheckerApiError);
    expect(e.status).toBe(502);
    expect(e.code).toBeNull();
  });

  it('error message never contains the secret key', async () => {
    const { client } = mk([json(401, { error: 'bad_key' })]);
    const e = await client.getEvent('e').catch((x) => x);
    expect(JSON.stringify(e) + e.message + e.stack).not.toContain('sk_test_123');
  });
});

describe('retries', () => {
  it('GET retried on 503 honouring Retry-After', async () => {
    const { client, calls, sleeps } = mk([
      json(503, { error: 'unavailable' }, { 'Retry-After': '2' }),
      json(200, { ok: true }),
    ]);
    await expect(client.getVisitor('v')).resolves.toEqual({ ok: true });
    expect(calls).toHaveLength(2);
    expect(sleeps).toEqual([2000]);
  });

  it('GET gives up after 2 retries with the final error', async () => {
    const { client, calls } = mk([json(500, {}), json(500, {}), json(429, { error: 'rate' }, { 'Retry-After': '1' })]);
    const e = await client.getHealth().catch((x) => x);
    expect(calls).toHaveLength(3);
    expect(e.status).toBe(429);
    expect(e.retryAfter).toBe(1);
  });

  it('caps absurd Retry-After', async () => {
    const { client, sleeps } = mk([json(429, {}, { 'Retry-After': '3600' }), json(200, {})]);
    await client.getStatus();
    expect(sleeps[0]).toBeLessThanOrEqual(10_000);
  });

  it('does not retry 4xx other than 429', async () => {
    const { client, calls } = mk([json(404, { error: 'not_found' })]);
    await client.getEvent('x').catch(() => undefined);
    expect(calls).toHaveLength(1);
  });

  it('billed POST is never retried', async () => {
    for (const status of [429, 503]) {
      const { client, calls } = mk([json(status, { error: 'x' }, { 'Retry-After': '1' }), json(200, {})]);
      await client.checkEligibility({ visitorId: 'v' }).catch(() => undefined);
      expect(calls).toHaveLength(1);
    }
  });

  it('PATCH and DELETE are never retried', async () => {
    const a = mk([json(503, {}), json(200, {})]);
    await a.client.updateEvent('e', {}).catch(() => undefined);
    expect(a.calls).toHaveLength(1);
    const b = mk([json(503, {}), json(200, {})]);
    await b.client.deleteVisitor('v').catch(() => undefined);
    expect(b.calls).toHaveLength(1);
  });
});
