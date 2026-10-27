// Thin client for the FingerPrint Checker Management API (/v1/management/*). One method per route.
// The key lives only in the Authorization header; it is scrubbed from everything that leaves this module.
import * as ids from './ids.js';

export const DEFAULT_API_URL = 'https://api.fpchecker.com';

export class FpcApiError extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    /** The server body, key-scrubbed; undefined when it was not JSON. */
    readonly body?: unknown,
  ) {
    super(`${error} (HTTP ${status})`);
    this.name = 'FpcApiError';
  }
}

export class FpcNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FpcNetworkError';
  }
}

export interface ClientOptions {
  apiUrl: string;
  key: string;
  fetch?: typeof fetch;
}

export interface EventQuery {
  visitorId?: string;
  limit?: number;
  since?: string;
  cursor?: string;
}

export type Json = Record<string, unknown>;

export function createClient(opts: ClientOptions) {
  const base = opts.apiUrl.replace(/\/+$/, '');
  const doFetch = opts.fetch ?? fetch;
  const scrub = (s: string): string => (opts.key === '' ? s : s.split(opts.key).join('[redacted]'));

  async function call(method: string, path: string, query?: Record<string, string | number | undefined>, body?: unknown): Promise<Json> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined) qs.set(k, String(v));
    const url = `${base}/v1/management/${path}${qs.size > 0 ? `?${qs}` : ''}`;
    const headers: Record<string, string> = { authorization: `Bearer ${opts.key}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    let res: Response;
    try {
      res = await doFetch(url, { method, headers, redirect: 'error', body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (err) {
      let origin = base;
      try {
        origin = new URL(base).origin;
      } catch {
        /* keep base */
      }
      const code = (err as { cause?: { code?: string } }).cause?.code;
      throw new FpcNetworkError(`could not reach ${origin}${code ? ` (${code})` : ''}`);
    }
    const text = scrub(await res.text());
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (!res.ok) {
      const e = (parsed as { error?: unknown } | undefined)?.error;
      throw new FpcApiError(res.status, typeof e === 'string' ? e : 'http_error', parsed);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new FpcApiError(res.status, 'invalid_response');
    return parsed as Json;
  }

  const p = (pid: string): string => `projects/${ids.projectId(pid)}`;

  return {
    listProjects: () => call('GET', 'projects'),
    getProject: (pid: string) => call('GET', p(pid)),
    createProject: (name: string) => call('POST', 'projects', undefined, { name }),
    createEnvironment: (pid: string, name: string) => call('POST', `${p(pid)}/environments`, undefined, { name: ids.envName(name) }),
    rotateKey: (pid: string, key: ids.KeyKind) => call('POST', `${p(pid)}/rotate`, undefined, { key: ids.keyKind(key) }),
    searchEvents: (pid: string, q: EventQuery = {}) =>
      call('GET', `${p(pid)}/events`, {
        visitorId: q.visitorId === undefined ? undefined : ids.visitorId(q.visitorId),
        limit: q.limit === undefined ? undefined : ids.limit(q.limit),
        start: q.since,
        cursor: q.cursor,
      }),
    getEvent: (pid: string, eid: string) => call('GET', `${p(pid)}/events/${ids.eventId(eid)}`),
    getVisitor: (pid: string, vid: string) => call('GET', `${p(pid)}/visitors/${ids.visitorId(vid)}`),
    getRuleset: (pid: string) => call('GET', `${p(pid)}/ruleset`),
    setRuleset: (pid: string, ruleset: unknown) => call('PUT', `${p(pid)}/ruleset`, undefined, ruleset),
    testRuleset: (pid: string, eid: string, ruleset: unknown) =>
      call('POST', `${p(pid)}/ruleset/test`, undefined, { eventId: ids.eventId(eid), ruleset }),
    listWebhooks: (pid: string) => call('GET', `${p(pid)}/webhooks`),
    getUsage: () => call('GET', 'usage'),
    listAudit: (q: { limit?: number; cursor?: string } = {}) =>
      call('GET', 'audit', { limit: q.limit === undefined ? undefined : ids.limit(q.limit), cursor: q.cursor }),
  };
}

export type Client = ReturnType<typeof createClient>;
