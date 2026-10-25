import { execFileSync } from 'node:child_process';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Stand-in for the vendored agent: defines the same global surface.
vi.mock('../src/vendor-source.generated.js', () => ({
  default: `
    window.__calls = [];
    class IdentifyV2Error extends Error { constructor(r, s) { super('identify v2 failed: ' + r); this.name = 'IdentifyV2Error'; this.reason = r; this.status = s; } }
    window.FpGuardAgent = {
      IdentifyV2Error,
      identifyV2: async (o) => {
        window.__calls.push(o);
        if (o.intentToken === 'bad') throw new IdentifyV2Error('intent_expired', 401);
        return { ok: true, attestation: 'att-' + window.__calls.length, eventId: 'ev-' + window.__calls.length, expiresIn: 300, sealedResult: 's-' + window.__calls.length };
      },
    };`,
}));

import { FpCheckerAgentError, load } from '../src/index.js';
import { resetLoaderForTests } from '../src/load.js';
import { clearMemoryCache } from '../src/cache.js';

const w = window as unknown as { __calls: Array<Record<string, unknown>>; FpGuardAgent?: unknown };
const scripts = () => document.querySelectorAll('script[data-fpchecker-agent]').length;

beforeEach(() => {
  delete w.FpGuardAgent;
  document.head.innerHTML = '';
  resetLoaderForTests();
  clearMemoryCache();
  window.localStorage.clear();
  window.sessionStorage.clear();
  vi.restoreAllMocks();
});

describe('load', () => {
  it('load twice (concurrently) injects one script', async () => {
    await Promise.all([load({ publishableKey: 'pk' }), load({ publishableKey: 'pk' })]);
    await load({ publishableKey: 'pk' });
    expect(scripts()).toBe(1);
  });

  it('load in SSR (no window) rejects with a typed error and touches nothing', async () => {
    vi.stubGlobal('window', undefined);
    const create = vi.spyOn(document, 'createElement');
    await expect(load({ publishableKey: 'pk' })).rejects.toMatchObject({ name: 'FpCheckerAgentError', code: 'ssr' });
    expect(create).not.toHaveBeenCalled();
    expect(scripts()).toBe(0);
    vi.unstubAllGlobals();
  });

  it('requires a publishableKey', async () => {
    await expect(load({ publishableKey: '' })).rejects.toMatchObject({ code: 'invalid_option' });
  });
});

describe('identify', () => {
  it('passes baseUrl (default endpoint), linkedId and tags to the agent', async () => {
    const fp = await load({ publishableKey: 'pk' });
    const r = await fp.identify({ intentToken: 't', linkedId: 'u1', tags: { a: 1 } });
    expect(r).toEqual({ attestation: 'att-1', eventId: 'ev-1', sealedResult: 's-1', expiresIn: 300, fromCache: false });
    expect(w.__calls[0]).toEqual({ baseUrl: 'https://api.fpchecker.com', publishableKey: 'pk', intentToken: 't', linkedId: 'u1', tags: { a: 1 } });
    const fp2 = await load({ publishableKey: 'pk', endpoint: 'https://x.test' });
    await fp2.identify({ intentToken: 't' });
    expect(w.__calls[1]).toMatchObject({ baseUrl: 'https://x.test' });
    expect(w.__calls[1]).not.toHaveProperty('linkedId');
  });

  it('wraps IdentifyV2Error in FpCheckerAgentError with reason and status', async () => {
    const fp = await load({ publishableKey: 'pk' });
    const e = await fp.identify({ intentToken: 'bad' }).catch((x) => x);
    expect(e).toBeInstanceOf(FpCheckerAgentError);
    expect(e).toMatchObject({ code: 'identify_failed', reason: 'intent_expired', status: 401 });
  });

  it('no cache by default: every call hits the agent', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', linkedId: 'u' });
    await fp.identify({ intentToken: 't', linkedId: 'u' });
    expect(w.__calls).toHaveLength(2);
  });
});

describe('cache', () => {
  for (const storage of ['memory', 'session', 'local'] as const) {
    it(`hit returns eventId/sealedResult, fromCache true, no attestation (${storage})`, async () => {
      const fp = await load({ publishableKey: 'pk' });
      const cache = { ttlSeconds: 60, storage };
      const first = await fp.identify({ intentToken: 't', linkedId: 'u', cache });
      const second = await fp.identify({ intentToken: 't', linkedId: 'u', cache });
      expect(w.__calls).toHaveLength(1);
      expect(second).toEqual({ eventId: first.eventId, sealedResult: first.sealedResult, fromCache: true });
      expect(second).not.toHaveProperty('attestation');
      expect(second).not.toHaveProperty('expiresIn');
    });
  }

  it('never writes the attestation to storage', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', linkedId: 'u', cache: { ttlSeconds: 60, storage: 'local' } });
    const dump = JSON.stringify({ ...window.localStorage });
    expect(dump).toContain('ev-1');
    expect(dump).not.toContain('att-1');
  });

  it('cache key differs per linkedId and per publishableKey', async () => {
    const fp = await load({ publishableKey: 'pk' });
    const cache = { ttlSeconds: 60, storage: 'memory' as const };
    await fp.identify({ intentToken: 't', linkedId: 'a', cache });
    const b = await fp.identify({ intentToken: 't', linkedId: 'b', cache });
    expect(b.fromCache).toBe(false);
    const other = await load({ publishableKey: 'pk2' });
    expect((await other.identify({ intentToken: 't', linkedId: 'a', cache })).fromCache).toBe(false);
    expect(w.__calls).toHaveLength(3);
  });

  it('expired entries are ignored', async () => {
    vi.useFakeTimers();
    try {
      const fp = await load({ publishableKey: 'pk' });
      const cache = { ttlSeconds: 10, storage: 'memory' as const };
      await fp.identify({ intentToken: 't', linkedId: 'u', cache });
      vi.advanceTimersByTime(9_000);
      expect((await fp.identify({ intentToken: 't', linkedId: 'u', cache })).fromCache).toBe(true);
      vi.advanceTimersByTime(2_000);
      expect((await fp.identify({ intentToken: 't', linkedId: 'u', cache })).fromCache).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('cache:false forces a fresh request', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', linkedId: 'u', cache: { ttlSeconds: 60, storage: 'memory' } });
    const r = await fp.identify({ intentToken: 't', linkedId: 'u', cache: false });
    expect(r.fromCache).toBe(false);
    expect(r.attestation).toBeDefined();
  });

  it.each([0, -1, 3601, 1.5, Number.NaN])('ttlSeconds %s rejected', async (ttlSeconds) => {
    const fp = await load({ publishableKey: 'pk' });
    await expect(fp.identify({ intentToken: 't', cache: { ttlSeconds, storage: 'memory' } })).rejects.toMatchObject({ code: 'invalid_option' });
    expect(w.__calls).toHaveLength(0);
  });

  it('ttlSeconds 3600 and 1 accepted', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', cache: { ttlSeconds: 3600, storage: 'memory' } });
    await fp.identify({ intentToken: 't', cache: { ttlSeconds: 1, storage: 'memory' } });
  });

  it('localStorage throwing -> identify works uncached', async () => {
    const fp = await load({ publishableKey: 'pk' });
    const real = window.localStorage;
    Object.defineProperty(window, 'localStorage', { configurable: true, get: () => { throw new DOMException('denied', 'SecurityError'); } });
    try {
      const cache = { ttlSeconds: 60, storage: 'local' as const };
      const a = await fp.identify({ intentToken: 't', linkedId: 'u', cache });
      const b = await fp.identify({ intentToken: 't', linkedId: 'u', cache });
      expect(a.fromCache).toBe(false);
      expect(b.fromCache).toBe(false);
      expect(w.__calls).toHaveLength(2);
    } finally {
      Object.defineProperty(window, 'localStorage', { value: real, configurable: true, writable: true });
    }
  });

  it('corrupt stored entry is a miss', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', linkedId: 'u', cache: { ttlSeconds: 60, storage: 'local' } });
    for (const k of Object.keys(window.localStorage)) window.localStorage.setItem(k, '{not json');
    const r = await fp.identify({ intentToken: 't', linkedId: 'u', cache: { ttlSeconds: 60, storage: 'local' } });
    expect(r.fromCache).toBe(false);
  });
});

describe('npm pack', () => {
  it('contains vendor min.js and no agent source', () => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { encoding: 'utf8' });
    const files: string[] = (JSON.parse(out)[0].files as Array<{ path: string }>).map((f) => f.path);
    expect(files).toContain('vendor/fp-agent.min.js');
    expect(files).toContain('package.json');
    expect(files.filter((f) => f.endsWith('.ts') && !f.endsWith('.d.ts'))).toEqual([]);
    expect(files.filter((f) => /identify-v2|event-fields|seal\.|pow\./.test(f))).toEqual([]);
    expect(files.some((f) => f.startsWith('src/') || f.startsWith('test/'))).toBe(false);
  });
});
