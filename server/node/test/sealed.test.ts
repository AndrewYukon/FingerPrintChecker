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
