import { createDecipheriv, createHash } from 'node:crypto';
import { SealedResultError } from './errors.js';

export interface SealedResult {
  version: 1;
  eventId: string;
  visitorId: string;
  projectId: string;
  linkedId: string | null;
  tags: Record<string, string> | null;
  timestamp: number;
  platform: string;
  proofStatus: string;
  [extra: string]: unknown;
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const MAGIC = Buffer.from('fps1', 'ascii');
const MIN_LEN = 4 + 4 + 12 + 16;

/** Canonical base64 only: Buffer.from() is lenient, so re-encode and compare. */
function strictBase64(input: unknown): Buffer | null {
  if (typeof input !== 'string' || input.length % 4 !== 0 || !B64.test(input)) return null;
  const bytes = Buffer.from(input, 'base64');
  return bytes.toString('base64') === input ? bytes : null;
}

/**
 * Decrypt a `sealedResult` from /v2/identify. `keys` are base64 32-byte project
 * keys (pass both active and previous during rotation). Throws SealedResultError.
 */
export function unsealResult(blob: string, keys: string[]): SealedResult {
  if (!Array.isArray(keys)) throw new SealedResultError('invalid_key');
  const keyBytes = keys.map((k) => {
    const b = strictBase64(k);
    if (!b || b.length !== 32) throw new SealedResultError('invalid_key');
    return b;
  });

  const raw = strictBase64(blob);
  if (!raw || raw.length < MIN_LEN) throw new SealedResultError('bad_format');
  if (!raw.subarray(0, 4).equals(MAGIC)) throw new SealedResultError('bad_format');

  const aad = raw.subarray(0, 8);
  const keyId = raw.subarray(4, 8);
  const candidates = keyBytes.filter((k) =>
    createHash('sha256').update(k).digest().subarray(0, 4).equals(keyId),
  );
  if (candidates.length === 0) throw new SealedResultError('unknown_key');

  const nonce = raw.subarray(8, 20);
  const ct = raw.subarray(20, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);

  let plain: Buffer | null = null;
  for (const key of candidates) {
    try {
      const d = createDecipheriv('aes-256-gcm', key, nonce);
      d.setAAD(aad);
      d.setAuthTag(tag);
      plain = Buffer.concat([d.update(ct), d.final()]);
      break;
    } catch {
      plain = null;
    }
  }
  if (!plain) throw new SealedResultError('decrypt_failed');

  let parsed: unknown;
  try {
    parsed = JSON.parse(plain.toString('utf8'));
  } catch {
    throw new SealedResultError('decrypt_failed');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
    throw new SealedResultError('decrypt_failed');
  if ((parsed as { version?: unknown }).version !== 1)
    throw new SealedResultError('unsupported_version');
  return parsed as SealedResult;
}
