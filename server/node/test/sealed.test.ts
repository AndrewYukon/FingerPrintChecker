import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SealedResultError, unsealResult } from '../src/index.js';

const vec = JSON.parse(
  readFileSync(new URL('../../../test-vectors/sealed-result-v1.json', import.meta.url), 'utf8'),
);

describe('unsealResult vectors', () => {
  for (const c of vec.cases) {
    it(c.name, () => {
      const keys = c.keys.map((k: string) => vec.keys[k]);
      if ('error' in c.expect) {
        let caught: unknown;
        try {
          unsealResult(c.blob, keys);
        } catch (e) {
          caught = e;
        }
        expect(caught).toBeInstanceOf(SealedResultError);
        expect((caught as SealedResultError).code).toBe(c.expect.error);
      } else {
        expect(unsealResult(c.blob, keys)).toEqual(c.expect);
      }
    });
  }

  it('rejects non-string blob and non-array keys without crashing', () => {
    expect(() => unsealResult(undefined as never, [vec.keys.a])).toThrow(SealedResultError);
    expect(() => unsealResult('x', 'nope' as never)).toThrow(SealedResultError);
  });
});

function seal(payload: Buffer): string {
  const key = Buffer.from(vec.keys.a, 'base64');
  const head = Buffer.concat([Buffer.from('fps1'), createHash('sha256').update(key).digest().subarray(0, 4)]);
  const nonce = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(head);
  const ct = Buffer.concat([c.update(payload), c.final()]);
  return Buffer.concat([head, nonce, ct, c.getAuthTag()]).toString('base64');
}

describe('unsealResult plaintext encoding', () => {
  it('positive control: well-formed payload unseals', () => {
    expect(unsealResult(seal(Buffer.from('{"version":1,"x":"é"}')), [vec.keys.a])).toEqual({ version: 1, x: 'é' });
  });
  it('invalid UTF-8 inside otherwise valid JSON is decrypt_failed', () => {
    const payload = Buffer.concat([Buffer.from('{"version":1,"x":"'), Buffer.from([0xff]), Buffer.from('"}')]);
    try {
      unsealResult(seal(payload), [vec.keys.a]);
      throw new Error('did not throw');
    } catch (e) {
      expect(e).toBeInstanceOf(SealedResultError);
      expect((e as SealedResultError).code).toBe('decrypt_failed');
    }
  });
});
