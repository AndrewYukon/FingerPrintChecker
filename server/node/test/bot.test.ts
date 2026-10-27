import { describe, expect, it } from 'vitest';
import { botCheckHeaders, FpChecker, FpCheckerApiError, parseWebhookEvent } from '../src/index.js';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const mk = (res: Response) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return res;
  }) as typeof fetch;
  return { client: new FpChecker({ secretKey: 'sk_test_123', fetch: f }), calls };
};

const verdict = {
  bot: {
    result: 'good',
    types: [],
    info: { id: 'googlebot', name: 'Googlebot', provider: 'Google', category: 'search_crawler', identity: 'verified' },
  },
  ip: { country: 'US', asn: 15169, asName: 'Google LLC', datacenter: true, tor: false, relay: false, blocklist: { result: false, sources: [] } },
  vpn: { result: false, methods: [] },
  proxy: { result: false, type: null },
};
const req = { method: 'GET', url: 'https://shop.example/pricing', ip: '66.249.66.1', headers: { 'user-agent': 'Googlebot/2.1' } };

describe('botCheck', () => {
  it('POSTs the request body to /v1/bot-check with the secret key and parses the verdict', async () => {
    const { client, calls } = mk(json(200, verdict));
    const r = await client.botCheck(req);
    const c = calls[0]!;
    expect(c.url).toBe('https://api.fpchecker.com/v1/bot-check');
    expect(c.init.method).toBe('POST');
    expect(JSON.parse(c.init.body as string)).toEqual(req);
    expect((c.init.headers as Record<string, string>)['X-Secret-Key']).toBe('sk_test_123');
    expect(r.bot.result).toBe('good');
    expect(r.bot.info?.identity).toBe('verified');
    expect(r.ip.asn).toBe(15169);
  });

  it('maps 400 to FpCheckerApiError carrying error and field', async () => {
    const { client } = mk(json(400, { ok: false, error: 'invalid_request', field: 'url' }));
    const err = await client.botCheck(req).catch((e) => e);
    expect(err).toBeInstanceOf(FpCheckerApiError);
    expect(err.status).toBe(400);
    expect(err.code).toBe('invalid_request');
    expect((err.body as { field: string }).field).toBe('url');
  });

  it.each([401, 429])('maps %i to FpCheckerApiError', async (status) => {
    const { client, calls } = mk(json(status, { ok: false, error: 'x' }));
    await expect(client.botCheck(req)).rejects.toMatchObject({ status });
    expect(calls).toHaveLength(1); // POST is never retried
  });
});

describe('botCheckHeaders', () => {
  const all = {
    'User-Agent': 'UA', Accept: 'text/html', 'Accept-Language': 'en', 'Accept-Encoding': 'gzip',
    'Sec-CH-UA': '"x"', 'Sec-CH-UA-Mobile': '?0', 'Sec-CH-UA-Platform': '"macOS"',
    'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1',
    Signature: 'sig1=:a:', 'Signature-Input': 'sig1=()', 'Signature-Agent': '"https://chatgpt.com"',
    'Upgrade-Insecure-Requests': '1',
  };
  const secret = { Cookie: 'sid=1', Authorization: 'Bearer x', 'X-Forwarded-For': '1.1.1.1', Host: 'a' };

  it('keeps exactly the allowed set from a Headers object and drops cookie/authorization', () => {
    const out = botCheckHeaders(new Headers({ ...all, ...secret }));
    expect(Object.keys(out).sort()).toEqual(Object.keys(all).map((k) => k.toLowerCase()).sort());
    expect(out).not.toHaveProperty('cookie');
    expect(out).not.toHaveProperty('authorization');
  });

  it('accepts Express-style req.headers (lower-case, arrays, undefined)', () => {
    const out = botCheckHeaders({ 'user-agent': 'UA', accept: ['a', 'b'], cookie: 'sid=1', authorization: 'x', 'accept-language': undefined });
    expect(out).toEqual({ 'user-agent': 'UA', accept: 'a, b' });
  });
});

describe('signals v1 and v2', () => {
  const ev = (signals: unknown) => JSON.stringify({ id: 'e', type: 'identify', data: { visitorId: 'v_1', signals } });

  it('parses a v1 event (no good, no info)', () => {
    const s = parseWebhookEvent(ev({ version: 1, bot: { result: 'bad', types: ['webdriver'] } })).data.signals!;
    expect(s.version).toBe(1);
    expect(s.bot?.result).toBe('bad');
    expect(s.bot?.info).toBeUndefined();
  });

  it('parses a v2 event with good and bot.info, and a null info', () => {
    const info = { id: 'googlebot', name: 'Googlebot', provider: 'Google', category: 'search_crawler', identity: 'verified' };
    const s = parseWebhookEvent(ev({ version: 2, bot: { result: 'good', types: [], info } })).data.signals!;
    expect(s.version).toBe(2);
    expect(s.bot?.result).toBe('good');
    expect(s.bot?.info).toEqual(info);
    const n = parseWebhookEvent(ev({ version: 2, bot: { result: 'not_detected', types: [], info: null } })).data.signals!;
    expect(n.bot?.info).toBeNull();
  });
});

describe('searchEvents bot filters', () => {
  it('sends botResult/botCategory/botIdentity/botId as bot_* query params', async () => {
    const { client, calls } = mk(json(200, { ok: true }));
    await client.searchEvents({ botResult: 'good', botCategory: 'ai_crawler', botIdentity: 'signed', botId: 'googlebot' });
    const u = new URL(calls[0]!.url);
    expect(Object.fromEntries(u.searchParams)).toEqual({
      bot_result: 'good', bot_category: 'ai_crawler', bot_identity: 'signed', bot_id: 'googlebot',
    });
  });
});
