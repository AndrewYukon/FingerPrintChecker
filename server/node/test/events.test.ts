import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FpChecker, parseEligibilityAnswer, parseWebhookEvent, verifyWebhookSignature } from '../src/index.js';

const vec = JSON.parse(
  readFileSync(new URL('../../../test-vectors/webhook-signature.json', import.meta.url), 'utf8'),
);

const ev = (data: Record<string, unknown>) => JSON.stringify({ id: 'evt_1', type: 'identify', data: { visitorId: 'v_1', ...data } });

describe('parseWebhookEvent', () => {
  it('ok_rule_action vector verifies and parses', () => {
    const c = vec.cases.find((x: { name: string }) => x.name === 'ok_rule_action');
    expect(() => verifyWebhookSignature({ rawBody: c.body, header: c.header, secret: vec.secret, now: c.now })).not.toThrow();
    const e = parseWebhookEvent(c.body);
    expect(e.data.proxied).toBe(true);
    expect(e.data.ruleAction).toEqual({ type: 'deny', ruleId: 'r_0a1b2c3d', ruleName: 'Block hosting', rulesetVersion: 3 });
  });

  it.each(['allow', 'human_check', 'deny', 'none'])('parses ruleAction type %s', (type) => {
    const e = parseWebhookEvent(ev({ ruleAction: { type, rulesetVersion: 1 }, proxied: false }));
    expect(e.data.ruleAction).toEqual({ type, rulesetVersion: 1 });
    expect(e.data.proxied).toBe(false);
  });

  it('keeps null ruleAction and tolerates missing fields', () => {
    expect(parseWebhookEvent(ev({ ruleAction: null })).data.ruleAction).toBeNull();
    const old = parseWebhookEvent(ev({}));
    expect(old.data.ruleAction).toBeUndefined();
    expect(old.data.proxied).toBeUndefined();
  });

  it('does not throw on an unknown rule type', () => {
    expect(parseWebhookEvent(ev({ ruleAction: { type: 'captcha', rulesetVersion: 2 } })).data.ruleAction?.type).toBe('captcha');
  });

  it('rejects non-events', () => {
    expect(() => parseWebhookEvent('{"a":1}')).toThrow(TypeError);
  });
});

describe('mobile integrity signals', () => {
  it('ok_mobile_signals vector verifies and parses the new fields', () => {
    const c = vec.cases.find((x: { name: string }) => x.name === 'ok_mobile_signals');
    expect(() => verifyWebhookSignature({ rawBody: c.body, header: c.header, secret: vec.secret, now: c.now })).not.toThrow();
    const m = parseWebhookEvent(c.body).data.signals?.mobile;
    expect(m).toMatchObject({ rooted: true, hooked: false, developerMode: true, vpn: true, locationSpoofed: null, factoryResetAt: null });
    expect(parseWebhookEvent(c.body).data.signals?.vpn?.methods).toContain('os_vpn');
  });

  it('old payloads: new fields are null, missing mobile stays absent', () => {
    const m = parseWebhookEvent(ev({ signals: { mobile: { emulator: false, attested: true, integrity: 'strong' } } })).data.signals?.mobile;
    expect(m?.rooted).toBeNull();
    expect(m?.clonedApp).toBeNull();
    expect(m?.factoryResetAt).toBeNull();
    expect(parseWebhookEvent(ev({ signals: { mobile: null } })).data.signals?.mobile).toBeNull();
    expect(parseWebhookEvent(ev({})).data.signals).toBeUndefined();
  });

  it('a non-boolean value is read as null, an unknown vpn method is dropped without throwing', () => {
    const e = parseWebhookEvent(ev({ signals: { vpn: { result: true, methods: ['os_vpn', 'future'] }, mobile: { rooted: 'yes', factoryResetAt: 5 } } }));
    expect(e.data.signals?.mobile?.rooted).toBeNull();
    expect(e.data.signals?.mobile?.factoryResetAt).toBeNull();
    expect(e.data.signals?.vpn?.methods).toEqual(['os_vpn']);
  });
});

describe('searchEvents mobile filters', () => {
  it('forwards rooted, hooked, emulator, mitm, locationSpoofed, clonedApp', async () => {
    const urls: string[] = [];
    const client = new FpChecker({ secretKey: 'sk_test_123', fetch: (async (u: string) => { urls.push(u); return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }); }) as unknown as typeof fetch });
    await client.searchEvents({ rooted: true, hooked: false, emulator: true, mitm: true, locationSpoofed: false, clonedApp: true });
    expect(urls[0]).toBe('https://api.fpchecker.com/v1/events?rooted=true&hooked=false&emulator=true&mitm=true&locationSpoofed=false&clonedApp=true');
  });
});

describe('parseEligibilityAnswer', () => {
  it('surfaces ruleId and open reasons', () => {
    const a = parseEligibilityAnswer({ ok: true, eligible: false, action: 'deny', reason: 'rule_deny', ruleId: 'r_1' });
    expect(a.ruleId).toBe('r_1');
    expect(a.reason).toBe('rule_deny');
    expect(parseEligibilityAnswer({ ok: true, eligible: true, reason: 'brand_new' }).ruleId).toBeUndefined();
  });
});
