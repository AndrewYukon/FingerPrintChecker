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

/**
 * Build the header map for `botCheck` from a `Headers` object or a Node/Express
 * `req.headers` object. Keeps only the allowed headers (lower-cased names) and drops the rest,
 * including Cookie and Authorization. Repeated values are joined with ", ".
 */
export function botCheckHeaders(source: HeaderSource): Record<string, string> {
  const out: Record<string, string> = {};
  const put = (name: string, value: HeaderValue) => {
    const key = name.toLowerCase();
    if (value === undefined || value === null || !BOT_CHECK_HEADERS.includes(key)) return;
    out[key] = Array.isArray(value) ? value.join(', ') : String(value);
  };
  if (typeof Headers !== 'undefined' && source instanceof Headers) source.forEach((v, k) => put(k, v));
  else for (const [k, v] of Object.entries(source as Record<string, HeaderValue>)) put(k, v);
  return out;
}
