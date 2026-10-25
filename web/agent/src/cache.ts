import { sha256Hex } from './sha256.js';
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

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

// Key = publishableKey + SHA-256(linkedId) + SHA-256(canonical tags). The raw linkedId (may be PII) never
// reaches storage. The intent token is deliberately not part of the key.
export function cacheKey(publishableKey: string, linkedId: string | undefined, tags?: Record<string, unknown>): string {
  const t = tags === undefined ? '' : canonical(tags);
  return `${PREFIX}${encodeURIComponent(publishableKey)}:${sha256Hex(linkedId ?? '')}:${sha256Hex(t)}`;
}

function area(kind: 'session' | 'local'): Storage | undefined {
  try {
    return kind === 'session' ? window.sessionStorage : window.localStorage;
  } catch {
    return undefined;
  }
}

function remove(key: string, c: CacheOptions): void {
  try {
    if (c.storage === 'memory') memory.delete(key);
    else area(c.storage)?.removeItem(key);
  } catch {
    /* ignore */
  }
}

export function readCache(key: string, c: CacheOptions, now = Date.now()): CachedValue | undefined {
  try {
    let e: Entry | undefined;
    if (c.storage === 'memory') e = memory.get(key);
    else {
      const raw = area(c.storage)?.getItem(key);
      if (raw === null || raw === undefined) return undefined;
      try {
        e = JSON.parse(raw) as Entry;
      } catch {
        e = undefined;
      }
    }
    if (e === undefined && c.storage === 'memory') return undefined;
    const valid =
      e !== undefined &&
      e !== null &&
      typeof e.eventId === 'string' &&
      typeof e.expiresAt === 'number' &&
      Number.isFinite(e.expiresAt) &&
      e.expiresAt > now &&
      e.expiresAt <= now + MAX_TTL_SECONDS * 1000 &&
      (e.sealedResult === undefined || typeof e.sealedResult === 'string');
    if (!valid || !e) {
      remove(key, c);
      return undefined;
    }
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
