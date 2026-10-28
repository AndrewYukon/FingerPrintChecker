import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';

it('the real vendored agent evaluates and exposes identifyV2 + IdentifyV2Error', () => {
  const src = readFileSync(resolve(__dirname, '../vendor/fp-agent.min.js'), 'utf8');
  expect(src.startsWith('/* @fingerprintchecker/agent vendored file. Source: fp-guard commit f8a89f3, agent 0.11.0')).toBe(true);
  delete (window as { FpGuardAgent?: unknown }).FpGuardAgent;
  // happy-dom 20+ does not run large inline <script> content reliably; evaluate in the window directly.
  (window as unknown as { eval: (s: string) => unknown }).eval(src);
  const g = (window as unknown as { FpGuardAgent: { identifyV2: unknown; IdentifyV2Error: new (r: string, s: number) => Error } }).FpGuardAgent;
  expect(typeof g.identifyV2).toBe('function');
  const e = new g.IdentifyV2Error('x', 400);
  expect(e.name).toBe('IdentifyV2Error');
});
