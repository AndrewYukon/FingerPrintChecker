// @vitest-environment node
import { expect, it } from 'vitest';
import { load } from '../src/index.js';

it('real Node (no window, no document): load() rejects with code ssr and touches no globals', async () => {
  const before = Object.getOwnPropertyNames(globalThis).sort();
  expect(typeof window).toBe('undefined');
  expect(typeof document).toBe('undefined');
  await expect(load({ publishableKey: 'pk' })).rejects.toMatchObject({ name: 'FpCheckerAgentError', code: 'ssr' });
  expect(Object.getOwnPropertyNames(globalThis).sort()).toEqual(before);
});
