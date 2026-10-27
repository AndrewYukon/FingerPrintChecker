/** Bot directory categories. The server may add values; treat an unknown one as `other`. */
export type BotCategory =
  | 'search_crawler' | 'ai_crawler' | 'ai_search' | 'ai_assistant' | 'ai_agent' | 'seo'
  | 'monitoring' | 'social_preview' | 'advertising' | 'aggregator' | 'scraping' | 'other'
  | (string & {});

/** How well a request matched a directory bot. */
export type BotIdentity = 'verified' | 'signed' | 'unknown' | 'spoofed' | (string & {});

/** `good` = a directory bot that is `verified` or `signed`. Treat an unknown value as `bad`. */
export type BotResult = 'not_detected' | 'good' | 'bad' | (string & {});

/** One entry of the Bot directory and how well the request matched it. */
export interface BotInfo {
  id: string;
  name: string;
  provider: string;
  category: BotCategory;
  identity: BotIdentity;
}

/** What the headers of a single request give away. Ignore a value you do not know. */
export type BotHeaderType = 'automation_tool' | 'headless' | 'missing_headers' | (string & {});

export interface BotCheckRequest {
  /** HTTP method of the request you received (case-insensitive). */
  method: string;
  /** The URL as the visitor requested it: original host and scheme, not your origin behind a CDN. */
  url: string;
  /** Client address of the request (IPv4 or IPv6, no zone id). */
  ip: string;
  /** Use `botCheckHeaders()` to build this from a framework request. */
  headers: Record<string, string>;
}

export interface BotCheckResult {
  bot: { result: BotResult; types: BotHeaderType[]; info: BotInfo | null };
  ip: {
    country: string | null;
    asn: number | null;
    asName: string | null;
    datacenter: boolean | null;
    tor: boolean | null;
    relay: boolean | null;
    blocklist: { result: boolean | null; sources: string[] };
  };
  vpn: { result: boolean | null; methods: string[] };
  proxy: { result: boolean | null; type: string | null };
  [k: string]: unknown;
}

/** The only request headers `botCheck` needs. Never Cookie or Authorization. */
export const BOT_CHECK_HEADERS: readonly string[] = [
  'user-agent', 'accept', 'accept-language', 'accept-encoding',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
  'signature', 'signature-input', 'signature-agent', 'upgrade-insecure-requests',
];

type HeaderValue = string | string[] | number | undefined | null;
type HeaderSource = Headers | Record<string, HeaderValue>;

/** Never forwarded, even when a signature covers them: they carry credentials. */
const NEVER_FORWARD = ['cookie', 'authorization', 'proxy-authorization'];
const MAX_EXTRA = 32;

/** Non-`@` component names covered by a `signature-input` value (lower-cased). */
function coveredHeaders(signatureInput: string): string[] {
  const names: string[] = [];
  for (const list of signatureInput.matchAll(/\(([^)]*)\)/g))
    for (const q of (list[1] ?? '').matchAll(/"([^"]*)"/g)) {
      const n = (q[1] ?? '').toLowerCase();
      if (n !== '' && !n.startsWith('@')) names.push(n);
    }
  return names;
}

/**
 * Build the header map for `botCheck` from a `Headers` object or a Node/Express
 * `req.headers` object. Keeps the allowed headers plus any header named as a covered component in the
 * request's `signature-input` (so a signed request can be verified); lower-cased names. Drops the rest,
 * including Cookie and Authorization, which are never forwarded. Repeated values are joined with ", ".
 */
export function botCheckHeaders(source: HeaderSource): Record<string, string> {
  const all: Record<string, string> = {};
  const put = (name: string, value: HeaderValue) => {
    if (value === undefined || value === null) return;
    all[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  };
  if (typeof Headers !== 'undefined' && source instanceof Headers) source.forEach((v, k) => put(k, v));
  else for (const [k, v] of Object.entries(source as Record<string, HeaderValue>)) put(k, v);

  const wanted = new Set(BOT_CHECK_HEADERS);
  const extra = coveredHeaders(all['signature-input'] ?? '').filter((n) => !NEVER_FORWARD.includes(n));
  for (const n of extra.slice(0, MAX_EXTRA)) wanted.add(n);
  return Object.fromEntries(Object.entries(all).filter(([k]) => wanted.has(k)));
}
