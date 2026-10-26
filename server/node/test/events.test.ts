import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseEligibilityAnswer, parseWebhookEvent, verifyWebhookSignature } from '../src/index.js';

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

describe('parseEligibilityAnswer', () => {
  it('surfaces ruleId and open reasons', () => {
    const a = parseEligibilityAnswer({ ok: true, eligible: false, action: 'deny', reason: 'rule_deny', ruleId: 'r_1' });
    expect(a.ruleId).toBe('r_1');
    expect(a.reason).toBe('rule_deny');
    expect(parseEligibilityAnswer({ ok: true, eligible: true, reason: 'brand_new' }).ruleId).toBeUndefined();
  });
});
