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

describe('redirects', () => {
  it('uses redirect:error so the secret is never forwarded cross-origin', async () => {
    const other: Array<Record<string, string>> = [];
    const f = (async (url: string | URL, init?: RequestInit) => {
      if (String(url).startsWith('https://evil.test')) {
        other.push(init?.headers as Record<string, string>);
        return json(200, {});
      }
      if (init?.redirect === 'error') throw new TypeError('fetch failed: redirect');
      return f(`https://evil.test/x`, init);
    }) as typeof fetch;
    const client = new FpChecker({ secretKey: 'sk_test_123', fetch: f, sleep: async () => {} });
    const e = await client.checkQuota({}).catch((x) => x);
    expect(e).toBeInstanceOf(FpCheckerApiError);
    expect(other).toEqual([]);
  });
});

describe('network failures', () => {
  it('wraps network errors as status 0 network_error with cause', async () => {
    const cause = new TypeError('fetch failed');
    const { client, calls } = mk([cause]);
    const e = await client.checkQuota({}).catch((x) => x);
    expect(e).toBeInstanceOf(FpCheckerApiError);
    expect([e.status, e.code, e.cause]).toEqual([0, 'network_error', cause]);
    expect(calls).toHaveLength(1);
  });

  it('wraps timeouts as code timeout', async () => {
    const t = Object.assign(new Error('timed out'), { name: 'TimeoutError' });
    const { client } = mk([t, t, t]);
    const e = await client.getHealth().catch((x) => x);
    expect([e.status, e.code, e.cause]).toEqual([0, 'timeout', t]);
  });

  it('GET retries network failures at most twice', async () => {
    const { client, calls } = mk([new TypeError('a'), new TypeError('b'), new TypeError('c'), json(200, {})]);
    const e = await client.getVisitor('v').catch((x) => x);
    expect(calls).toHaveLength(3);
    expect(e.code).toBe('network_error');
    const ok = mk([new TypeError('a'), json(200, { ok: true })]);
    await expect(ok.client.getVisitor('v')).resolves.toEqual({ ok: true });
  });

  it('PATCH/DELETE/POST never retry network failures', async () => {
    for (const call of [
      (c: FpChecker) => c.updateEvent('e', {}),
      (c: FpChecker) => c.deleteVisitor('v'),
      (c: FpChecker) => c.checkEligibility({}),
    ]) {
      const { client, calls } = mk([new TypeError('x'), json(200, {})]);
      await call(client).catch(() => undefined);
      expect(calls).toHaveLength(1);
    }
  });
});

describe('baseUrl', () => {
  it('rejects non-https except loopback', () => {
    expect(() => new FpChecker({ secretKey: 'sk', baseUrl: 'http://api.example.com' })).toThrow(TypeError);
    expect(() => new FpChecker({ secretKey: 'sk', baseUrl: 'not a url' })).toThrow(TypeError);
    for (const u of ['http://localhost:8787', 'http://127.0.0.1:1', 'http://[::1]:2', 'https://x.test'])
      expect(() => new FpChecker({ secretKey: 'sk', baseUrl: u })).not.toThrow();
  });
});

describe('every operation (table from openapi)', () => {
  const deref = (p: any) =>
    p.$ref ? p.$ref.split('/').slice(1).reduce((o: any, k: string) => o[k], spec) : p;
  const ops: Array<{ id: string; method: string; path: string; params: Array<{ name: string; in: string }>; body: boolean; sec: string[] }> = [];
  for (const [path, item] of Object.entries<Record<string, any>>(spec.paths))
    for (const [method, op] of Object.entries<any>(item))
      if (op?.operationId)
        ops.push({
          id: op.operationId,
          method: method.toUpperCase(),
          path,
          params: [...(item.parameters ?? []), ...(op.parameters ?? [])].map(deref),
          body: !!op.requestBody,
          sec: (op.security ?? spec.security ?? []).flatMap((s: object) => Object.keys(s)),
        });

  it('table is complete', () => expect(ops.length).toBeGreaterThanOrEqual(17));

  for (const op of ops) {
    it(`${op.id}: ${op.method} ${op.path}`, async () => {
      const { client, calls } = mk([json(200, { ok: true })], { publishableKey: 'pk_test_9' });
      const pathParams = op.params.filter((p) => p.in === 'path');
      const args: unknown[] = pathParams.map((_, i) => `id/${i} x`);
      const queryParams = op.params.filter((p) => p.in === 'query');
      if (op.body) args.push({ a: 1 });
      else if (queryParams.length) args.push({ intent: 'i' });
      await (client as any)[op.id](...args);
      const c = calls[0]!;
      const u = new URL(c.url);
      let expectedPath = op.path;
      pathParams.forEach((p, i) => (expectedPath = expectedPath.replace(`{${p.name}}`, encodeURIComponent(`id/${i} x`))));
      expect(u.pathname).toBe(expectedPath);
      expect(c.init.method).toBe(op.method);
      const h = c.init.headers as Record<string, string>;
      const has = (k: string) => Object.keys(h).some((x) => x.toLowerCase() === k.toLowerCase());
      expect(has('X-Secret-Key')).toBe(op.sec.includes('secretKey'));
      expect(has('X-Publishable-Key')).toBe(op.sec.includes('publishableKey'));
      if (op.sec.includes('secretKey')) expect(h['X-Secret-Key']).toBe('sk_test_123');
      expect(c.url).not.toContain('sk_test');
      expect(c.url).not.toContain('pk_test');
    });
  }
});
