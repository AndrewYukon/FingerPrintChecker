import { FpCheckerApiError } from './errors.js';

export type Json = Record<string, unknown>;
/** Any 2xx body, including `{ ok: false, error|reason }` refusals. */
export type ApiResponse = { ok?: boolean; error?: string; reason?: string; [k: string]: unknown };
export type QueryParams = Record<string, string | number | boolean | undefined | null>;

export interface FpCheckerOptions {
  /** Project secret key (`sk_…`). Backend only; sent in X-Secret-Key, never in a URL. */
  secretKey: string;
  /** Default https://api.fpchecker.com */
  baseUrl?: string;
  /** Custom fetch (defaults to global fetch). */
  fetch?: typeof fetch;
  /** Publishable key (`pk_…`), only needed for identify() and getChallenge(). */
  publishableKey?: string;
  /** Per-request timeout in ms (default 30000). */
  timeoutMs?: number;
  /** Max wait between GET retries in ms (default 10000). */
  maxRetryDelayMs?: number;
  /** Override the delay function (tests). */
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_BASE = 'https://api.fpchecker.com';
const MAX_RETRIES = 2;

interface RequestSpec {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  query?: QueryParams;
  body?: Json;
  publishable?: boolean;
  noAuth?: boolean;
}

export class FpChecker {
  readonly #secretKey: string;
  readonly #publishableKey: string | undefined;
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;
  readonly #maxRetryDelayMs: number;
  readonly #sleep: (ms: number) => Promise<void>;

  constructor(options: FpCheckerOptions) {
    if (!options || typeof options.secretKey !== 'string' || options.secretKey === '')
      throw new TypeError('FpChecker: secretKey is required');
    this.#secretKey = options.secretKey;
    this.#publishableKey = options.publishableKey;
    this.#baseUrl = validateBaseUrl(options.baseUrl ?? DEFAULT_BASE);
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#maxRetryDelayMs = options.maxRetryDelayMs ?? 10_000;
    this.#sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Keep the secret out of util.inspect / JSON / console.log of the client. */
  toJSON(): Json {
    return { baseUrl: this.#baseUrl };
  }

  // --- operations (method name = operationId) ---
  createIntent(body: Json) { return this.#call({ method: 'POST', path: '/v2/intents', body }); }
  getChallenge(query: { intent: string; difficulty?: number }) {
    return this.#call({ method: 'GET', path: '/v2/challenge', query, publishable: true });
  }
  identify(body: Json) { return this.#call({ method: 'POST', path: '/v2/identify', body, publishable: true }); }
  checkEligibility(body: Json) { return this.#call({ method: 'POST', path: '/v1/eligibility', body }); }
  releaseEligibility(body: Json) { return this.#call({ method: 'POST', path: '/v1/eligibility/release', body }); }
  checkQuota(body: Json) { return this.#call({ method: 'POST', path: '/v1/quota', body }); }
  bindSubject(body: Json) { return this.#call({ method: 'POST', path: '/v1/subjects/bind', body }); }
  relateSubjects(body: Json) { return this.#call({ method: 'POST', path: '/v1/subjects/relation', body }); }
  sendFeedback(body: Json) { return this.#call({ method: 'POST', path: '/v1/feedback', body }); }
  getClaimFlags(query: QueryParams = {}) { return this.#call({ method: 'GET', path: '/v1/claims/flags', query }); }
  searchEvents(query: QueryParams = {}) { return this.#call({ method: 'GET', path: '/v1/events', query }); }
  getEvent(eventId: string) { return this.#call({ method: 'GET', path: `/v1/events/${enc(eventId)}` }); }
  updateEvent(eventId: string, body: Json) {
    return this.#call({ method: 'PATCH', path: `/v1/events/${enc(eventId)}`, body });
  }
  getVisitor(visitorId: string) { return this.#call({ method: 'GET', path: `/v1/visitors/${enc(visitorId)}` }); }
  deleteVisitor(visitorId: string) { return this.#call({ method: 'DELETE', path: `/v1/visitors/${enc(visitorId)}` }); }
  getHealth() { return this.#call({ method: 'GET', path: '/health', noAuth: true }); }
  getStatus() { return this.#call({ method: 'GET', path: '/status', noAuth: true }); }

  async #call(spec: RequestSpec): Promise<ApiResponse> {
    const url = this.#baseUrl + spec.path + queryString(spec.query);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (spec.publishable) {
      if (!this.#publishableKey) throw new TypeError('FpChecker: publishableKey is required for this operation');
      headers['X-Publishable-Key'] = this.#publishableKey;
    } else if (!spec.noAuth) {
      headers['X-Secret-Key'] = this.#secretKey;
    }
    let body: string | undefined;
    if (spec.body !== undefined) {
      body = JSON.stringify(spec.body);
      headers['Content-Type'] = 'application/json';
    }
    const maxRetries = spec.method === 'GET' ? MAX_RETRIES : 0;

    for (let attempt = 0; ; attempt++) {
      let res: Response;
      let parsed: unknown;
      try {
        res = await this.#fetch(url, {
          method: spec.method,
          headers,
          body,
          // A redirect would forward X-Secret-Key to another origin.
          redirect: 'error',
          signal: AbortSignal.timeout(this.#timeoutMs),
        });
        parsed = await readBody(res);
      } catch (cause) {
        const timeout = cause instanceof Error && (cause.name === 'TimeoutError' || cause.name === 'AbortError');
        const err = new FpCheckerApiError(0, timeout ? 'timeout' : 'network_error', null, null, cause);
        if (attempt < maxRetries) {
          await this.#sleep(Math.min(500 * 2 ** attempt, this.#maxRetryDelayMs));
          continue;
        }
        throw err;
      }
      if (res.ok) return (parsed ?? {}) as ApiResponse;

      const retryAfter = parseRetryAfter(res.headers.get('retry-after'));
      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && attempt < maxRetries) {
        const wait = retryAfter !== null ? retryAfter * 1000 : 500 * 2 ** attempt;
        await this.#sleep(Math.min(wait, this.#maxRetryDelayMs));
        continue;
      }
      throw new FpCheckerApiError(res.status, errorCode(parsed), retryAfter, parsed);
    }
  }
}

const enc = encodeURIComponent;

function validateBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new TypeError('FpChecker: baseUrl is not a valid URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback))
    throw new TypeError('FpChecker: baseUrl must be https (http only for localhost, 127.0.0.1, [::1])');
  return raw.replace(/\/+$/, '');
}

function queryString(q?: QueryParams): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null) p.append(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text === '') return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function errorCode(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const b = body as { error?: unknown; reason?: unknown };
  const c = b.error ?? b.reason;
  return typeof c === 'string' ? c : null;
}

function parseRetryAfter(v: string | null): number | null {
  if (v === null || !/^\d{1,9}$/.test(v.trim())) return null;
  return Number(v.trim());
}
