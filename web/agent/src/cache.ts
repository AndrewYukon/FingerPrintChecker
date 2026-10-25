import { FpCheckerAgentError, type CacheOptions } from './types.js';

export const MAX_TTL_SECONDS = 3600;
const PREFIX = 'fpchecker:agent:v1:';

interface Entry {
  eventId: string;
  sealedResult?: string;
  expiresAt: number;
}

export interface CachedValue {
  eventId: string;
  sealedResult?: string;
}

const memory = new Map<string, Entry>();

export function validateCache(c: CacheOptions): void {
  if (!Number.isInteger(c.ttlSeconds) || c.ttlSeconds < 1 || c.ttlSeconds > MAX_TTL_SECONDS) {
    throw new FpCheckerAgentError('invalid_option', `cache.ttlSeconds must be an integer 1..${MAX_TTL_SECONDS}`);
  }
  if (c.storage !== 'memory' && c.storage !== 'session' && c.storage !== 'local') {
    throw new FpCheckerAgentError('invalid_option', "cache.storage must be 'memory', 'session' or 'local'");
  }
}

// Key = publishableKey + linkedId, encoded (JSON of the pair, percent-encoded) so no delimiter ambiguity.
export function cacheKey(publishableKey: string, linkedId: string | undefined): string {
  return PREFIX + encodeURIComponent(JSON.stringify([publishableKey, linkedId ?? null]));
}

function area(kind: 'session' | 'local'): Storage | undefined {
  try {
    return kind === 'session' ? window.sessionStorage : window.localStorage;
  } catch {
    return undefined;
  }
}

export function readCache(key: string, c: CacheOptions, now = Date.now()): CachedValue | undefined {
  try {
    let e: Entry | undefined;
    if (c.storage === 'memory') e = memory.get(key);
    else {
      const raw = area(c.storage)?.getItem(key);
      e = raw ? (JSON.parse(raw) as Entry) : undefined;
    }
    if (!e || typeof e.eventId !== 'string' || typeof e.expiresAt !== 'number' || e.expiresAt <= now) return undefined;
    return e.sealedResult === undefined ? { eventId: e.eventId } : { eventId: e.eventId, sealedResult: e.sealedResult };
  } catch {
    return undefined;
  }
}

/** Stores only eventId and sealedResult; never the attestation. */
export function writeCache(key: string, c: CacheOptions, v: CachedValue, now = Date.now()): void {
  const entry: Entry = { eventId: v.eventId, expiresAt: now + c.ttlSeconds * 1000 };
  if (v.sealedResult !== undefined) entry.sealedResult = v.sealedResult;
  try {
    if (c.storage === 'memory') memory.set(key, entry);
    else area(c.storage)?.setItem(key, JSON.stringify(entry));
  } catch {
    /* storage failure = no caching */
  }
}

export function clearMemoryCache(): void {
  memory.clear();
}
