import { FpCheckerAgentError } from './types.js';

export const DEFAULT_ENDPOINT = 'https://api.fpchecker.com';
const SCRIPT_ATTR = 'data-fpchecker-agent';

export interface IdentifyV2Fn {
  (o: {
    baseUrl: string;
    publishableKey: string;
    intentToken: string;
    linkedId?: string;
    tags?: Record<string, unknown>;
  }): Promise<Record<string, unknown>>;
}
export interface AgentGlobal {
  identifyV2: IdentifyV2Fn;
  IdentifyV2Error: new (...a: never[]) => Error & { reason: string; status: number };
}

let pending: Promise<AgentGlobal> | undefined;

function agentGlobal(): AgentGlobal | undefined {
  const g = (globalThis as { FpGuardAgent?: AgentGlobal }).FpGuardAgent;
  return g && typeof g.identifyV2 === 'function' ? g : undefined;
}

function injectInline(source: string, nonce: string | null | undefined): HTMLScriptElement {
  const el = document.createElement('script');
  el.setAttribute(SCRIPT_ATTR, '');
  if (nonce) el.setAttribute('nonce', nonce);
  el.textContent = source;
  document.head.appendChild(el);
  return el;
}

function injectSrc(url: string, nonce: string | null | undefined): Promise<HTMLScriptElement> {
  return new Promise((resolve, reject) => {
    const el = document.createElement('script');
    el.setAttribute(SCRIPT_ATTR, '');
    if (nonce) el.setAttribute('nonce', nonce);
    el.async = true;
    el.addEventListener('load', () => resolve(el));
    el.addEventListener('error', () => {
      el.remove();
      reject(new Error(`could not fetch ${url}`));
    });
    el.src = url;
    document.head.appendChild(el);
  });
}

/**
 * Inject the agent into the page once; concurrent callers share one promise.
 * Inline (bundled string) by default; with `scriptUrl`, a <script src> element.
 */
export function loadAgentScript(scriptUrl?: string): Promise<AgentGlobal> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return Promise.reject(new FpCheckerAgentError('ssr', 'load() needs a browser; call it from client-side code only'));
  }
  const existing = agentGlobal();
  if (existing) return Promise.resolve(existing);
  if (pending) return pending;
  pending = (async () => {
    let el: HTMLScriptElement | undefined;
    try {
      const nonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content');
      // A leftover element without the global is a failed earlier attempt: replace it.
      document.querySelectorAll(`script[${SCRIPT_ATTR}]`).forEach((n) => n.remove());
      if (scriptUrl) {
        el = await injectSrc(scriptUrl, nonce);
      } else {
        // Dynamic import keeps the 400 KB string out of bundles that never call load().
        const { default: source } = await import('./vendor-source.generated.js');
        el = injectInline(source, nonce);
      }
      const g = agentGlobal();
      if (!g) throw new Error('agent script did not define FpGuardAgent (blocked by CSP?)');
      return g;
    } catch (e) {
      el?.remove();
      document.querySelectorAll(`script[${SCRIPT_ATTR}]`).forEach((n) => n.remove());
      pending = undefined; // allow a retry
      if (e instanceof FpCheckerAgentError) throw e;
      throw new FpCheckerAgentError('load_failed', `could not load the agent: ${(e as Error).message}`);
    }
  })();
  return pending;
}

export function resetLoaderForTests(): void {
  pending = undefined;
}
