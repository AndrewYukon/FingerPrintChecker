import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockSrc = vi.hoisted(() => ({ broken: false }));
vi.mock('../src/vendor-source.generated.js', () => ({
  get default() {
    return mockSrc.broken
      ? '/* CSP-blocked stand-in: defines nothing */'
      : `window.__calls = window.__calls || [];
         window.FpGuardAgent = { identifyV2: async (o) => { window.__calls.push(o); return { eventId: 'ev-' + window.__calls.length, attestation: 'a', sealedResult: 's' }; } };`;
  },
}));

import { load } from '../src/index.js';
import { cacheKey, clearMemoryCache, readCache, writeCache } from '../src/cache.js';
import { resetLoaderForTests } from '../src/load.js';

const w = window as unknown as { __calls?: unknown[]; FpGuardAgent?: unknown };
const els = () => document.querySelectorAll('script[data-fpchecker-agent]');
const tick = () => new Promise((r) => setTimeout(r, 0));

// happy-dom would fetch (and auto-fire load/error for) a script with a src attribute. Capture the src
// property instead so each test fires load/error itself, deterministically.
function captureSrc(): void {
  const real = document.createElement.bind(document);
  vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
    const el = real(tag);
    if (tag === 'script') {
      let src = '';
      Object.defineProperty(el, 'src', { configurable: true, get: () => src, set: (v: string) => { src = v; } });
    }
    return el;
  }) as typeof document.createElement);
}

beforeEach(() => {
  vi.restoreAllMocks();
  captureSrc();
  delete w.FpGuardAgent;
  w.__calls = [];
  mockSrc.broken = false;
  document.head.innerHTML = '';
  resetLoaderForTests();
  clearMemoryCache();
  window.localStorage.clear();
});

describe('cache key (P23)', () => {
  it('differs per tags, canonical regardless of key order, ignores intentToken', async () => {
    const k = (l: string | undefined, t?: Record<string, unknown>) => cacheKey('pk', l, t);
    expect(k('u', { a: 1, b: { y: 1, x: 2 } })).toBe(k('u', { b: { x: 2, y: 1 }, a: 1 }));
    expect(k('u', { a: 1 })).not.toBe(k('u', { a: 2 }));
    expect(k('u')).not.toBe(k('u', { a: 1 }));
    const fp = await load({ publishableKey: 'pk' });
    const cache = { ttlSeconds: 60, storage: 'memory' as const };
    await fp.identify({ intentToken: 't1', linkedId: 'u', cache });
    const r = await fp.identify({ intentToken: 't2', linkedId: 'u', cache });
    expect(r.fromCache).toBe(true); // intent is deliberately not part of the key
  });

  it('raw linkedId never appears in storage keys or values', async () => {
    const fp = await load({ publishableKey: 'pk' });
    await fp.identify({ intentToken: 't', linkedId: 'alice@example.com', cache: { ttlSeconds: 60, storage: 'local' } });
    expect(window.localStorage.length).toBe(1);
    const dump = JSON.stringify({ ...window.localStorage });
    expect(dump).not.toContain('alice');
    expect(dump).not.toContain('example.com');
  });
});

describe('cache expiry hardening', () => {
  const c = { ttlSeconds: 60, storage: 'local' as const };
  it('expired entry is deleted from storage on read', () => {
    writeCache('k', c, { eventId: 'e', sealedResult: 's' }, 1000);
    expect(window.localStorage.length).toBe(1);
    expect(readCache('k', c, 1000 + 61_000)).toBeUndefined();
    expect(window.localStorage.length).toBe(0);
  });
  it.each([
    ['too far in future', { eventId: 'e', expiresAt: 1000 + 3601_000 }],
    ['non-finite', { eventId: 'e', expiresAt: 'x' }],
    ['malformed', { nope: true }],
  ])('%s -> miss and deleted', (_n, entry) => {
    window.localStorage.setItem('k', JSON.stringify(entry));
    expect(readCache('k', c, 1000)).toBeUndefined();
    expect(window.localStorage.length).toBe(0);
  });
  it('exactly now+3600s is still accepted', () => {
    window.localStorage.setItem('k', JSON.stringify({ eventId: 'e', expiresAt: 1000 + 3600_000 }));
    expect(readCache('k', c, 1000)).toEqual({ eventId: 'e' });
  });
});

describe('inline load failure', () => {
  it('removes the injected element and a retry injects again', async () => {
    mockSrc.broken = true;
    await expect(load({ publishableKey: 'pk' })).rejects.toMatchObject({ code: 'load_failed' });
    expect(els()).toHaveLength(0);
    mockSrc.broken = false;
    const fp = await load({ publishableKey: 'pk' });
    expect(els()).toHaveLength(1);
    expect((await fp.identify({ intentToken: 't' })).eventId).toBe('ev-1');
  });
});

describe('scriptUrl (P22)', () => {
  it('injects <script src> async, not inline, once; resolves on load', async () => {
    const p = Promise.all([
      load({ publishableKey: 'pk', scriptUrl: '/static/fp-agent.min.js' }),
      load({ publishableKey: 'pk', scriptUrl: '/static/fp-agent.min.js' }),
    ]);
    await tick();
    expect(els()).toHaveLength(1);
    const el = els()[0] as HTMLScriptElement;
    expect(el.src).toBe('/static/fp-agent.min.js');
    expect(el.async).toBe(true);
    expect(el.textContent).toBe('');
    w.FpGuardAgent = { identifyV2: async () => ({ eventId: 'ev-url' }) };
    el.dispatchEvent(new Event('load'));
    const [fp] = await p;
    expect((await fp.identify({ intentToken: 't' })).eventId).toBe('ev-url');
  });

  it('onerror -> load_failed, element removed, retry injects again', async () => {
    const p = load({ publishableKey: 'pk', scriptUrl: '/x.js' });
    await tick();
    els()[0]!.dispatchEvent(new Event('error'));
    await expect(p).rejects.toMatchObject({ code: 'load_failed' });
    expect(els()).toHaveLength(0);
    const p2 = load({ publishableKey: 'pk', scriptUrl: '/x.js' });
    await tick();
    expect(els()).toHaveLength(1);
    w.FpGuardAgent = { identifyV2: async () => ({ eventId: 'e' }) };
    els()[0]!.dispatchEvent(new Event('load'));
    await p2;
  });

  it('load event without the global -> load_failed, element removed', async () => {
    const p = load({ publishableKey: 'pk', scriptUrl: '/x.js' });
    await tick();
    els()[0]!.dispatchEvent(new Event('load'));
    await expect(p).rejects.toMatchObject({ code: 'load_failed' });
    expect(els()).toHaveLength(0);
  });
});

import { sha256Hex } from '../src/sha256.js';
describe('sha256', () => {
  it('matches known vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Hex('a'.repeat(1000))).toBe('41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
  });
});
