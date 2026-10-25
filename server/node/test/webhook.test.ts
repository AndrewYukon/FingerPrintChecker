import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { WebhookSignatureError, verifyWebhookSignature } from '../src/index.js';

const vec = JSON.parse(
  readFileSync(new URL('../../../test-vectors/webhook-signature.json', import.meta.url), 'utf8'),
);

describe('verifyWebhookSignature vectors', () => {
  for (const c of vec.cases) {
    it(c.name, () => {
      const run = () =>
        verifyWebhookSignature({ rawBody: c.body, header: c.header, secret: vec.secret, now: c.now });
      if (c.expect === true) {
        expect(run).not.toThrow();
      } else {
        let caught: unknown;
        try {
          run();
        } catch (e) {
          caught = e;
        }
        expect(caught).toBeInstanceOf(WebhookSignatureError);
        expect((caught as WebhookSignatureError).code).toBe(c.expect.error);
      }
    });
  }

  it('accepts Buffer bodies and honours toleranceSec', () => {
    const c = vec.cases.find((x: { name: string }) => x.name === 'edge_past_300');
    expect(() =>
      verifyWebhookSignature({
        rawBody: Buffer.from(c.body),
        header: c.header,
        secret: vec.secret,
        now: c.now,
        toleranceSec: 10,
      }),
    ).toThrow(WebhookSignatureError);
  });

  it('missing header is malformed_header', () => {
    expect(() =>
      verifyWebhookSignature({ rawBody: 'x', header: undefined as never, secret: 's', now: 1 }),
    ).toThrow(/malformed_header|malformed/);
  });
});
