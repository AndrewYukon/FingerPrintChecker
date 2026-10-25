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

/** Inject the vendored agent into the page once; concurrent callers share one promise. */
export function loadAgentScript(): Promise<AgentGlobal> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return Promise.reject(new FpCheckerAgentError('ssr', 'load() needs a browser; call it from client-side code only'));
  }
  const existing = agentGlobal();
  if (existing) return Promise.resolve(existing);
  if (pending) return pending;
  pending = (async () => {
    try {
      // Dynamic import keeps the 400 KB string out of bundles that never call load().
      const { default: source } = await import('./vendor-source.generated.js');
      if (!document.querySelector(`script[${SCRIPT_ATTR}]`)) {
        const el = document.createElement('script');
        el.setAttribute(SCRIPT_ATTR, '');
        const nonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content');
        if (nonce) el.setAttribute('nonce', nonce);
        el.textContent = source;
        document.head.appendChild(el);
      }
      const g = agentGlobal();
      if (!g) throw new Error('agent script did not define FpGuardAgent (blocked by CSP?)');
      return g;
    } catch (e) {
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
