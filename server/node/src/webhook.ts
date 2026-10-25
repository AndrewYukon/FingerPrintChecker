import { createHmac, timingSafeEqual } from 'node:crypto';
import { WebhookSignatureError } from './errors.js';

export interface VerifyWebhookOptions {
  /** The exact bytes received. Never a re-serialised object. */
  rawBody: string | Uint8Array;
  /** Value of the `FPC-Signature` header. */
  header: string;
  /** Webhook signing secret (`whsec_…`). */
  secret: string;
  /** Allowed clock skew in seconds, both directions (default 300). */
  toleranceSec?: number;
  /** Verifier clock in unix seconds (default: now). */
  now?: number;
}

const WS = /[ \t\r\n]/;
const T_RE = /^[0-9]{1,12}$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;

function parseHeader(header: unknown): { tRaw: string; t: number; v1: string[] } {
  if (typeof header !== 'string' || WS.test(header)) throw new WebhookSignatureError('malformed_header');
  let t: string | null = null;
  const v1: string[] = [];
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (part === '' || eq < 0) throw new WebhookSignatureError('malformed_header');
    const key = part.slice(0, eq);
    const value = part.slice(eq + 1);
    if (key === 't') {
      if (t !== null) throw new WebhookSignatureError('malformed_header');
      t = value;
    } else if (key === 'v1') {
      v1.push(value);
    }
  }
  if (t === null || !T_RE.test(t) || v1.length === 0) throw new WebhookSignatureError('malformed_header');
  return { tRaw: t, t: Number(t), v1 };
}

/** Throws WebhookSignatureError unless the header is a valid, fresh signature of rawBody. */
export function verifyWebhookSignature(opts: VerifyWebhookOptions): void {
  const { rawBody, header, secret, toleranceSec = 300 } = opts;
  if (typeof toleranceSec !== 'number' || !Number.isFinite(toleranceSec) || toleranceSec < 0)
    throw new TypeError('verifyWebhookSignature: toleranceSec must be a finite number >= 0');
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const { tRaw, t, v1 } = parseHeader(header);

  const body = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : Buffer.from(rawBody);
  const expected = createHmac('sha256', secret)
    .update(Buffer.concat([Buffer.from(`${tRaw}.`), body]))
    .digest();
  let match = false;
  for (const candidate of v1) {
    if (!HEX64.test(candidate)) continue;
    if (timingSafeEqual(Buffer.from(candidate, 'hex'), expected)) match = true;
  }
  if (!match) throw new WebhookSignatureError('bad_signature');

  if (now - t > toleranceSec) throw new WebhookSignatureError('expired');
  if (t - now > toleranceSec) throw new WebhookSignatureError('future');
}
