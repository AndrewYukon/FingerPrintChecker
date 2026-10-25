/** Thrown for any non-2xx API response. 2xx bodies (including ok:false) are returned as data. */
export class FpCheckerApiError extends Error {
  readonly status: number;
  /** `body.error ?? body.reason`, or null when the body carried neither. */
  readonly code: string | null;
  /** Retry-After in seconds, or null. */
  readonly retryAfter: number | null;
  readonly body: unknown;

  constructor(status: number, code: string | null, retryAfter: number | null, body: unknown, cause?: unknown) {
    super(`FpChecker API error: HTTP ${status}${code ? ` (${code})` : ''}`, cause === undefined ? undefined : { cause });
    this.name = 'FpCheckerApiError';
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
    this.body = body;
  }
}

export type SealedErrorCode =
  | 'bad_format'
  | 'unknown_key'
  | 'decrypt_failed'
  | 'invalid_key'
  | 'unsupported_version';

export class SealedResultError extends Error {
  readonly code: SealedErrorCode;
  constructor(code: SealedErrorCode) {
    super(`sealed result: ${code}`);
    this.name = 'SealedResultError';
    this.code = code;
  }
}

export type WebhookErrorCode = 'expired' | 'future' | 'bad_signature' | 'malformed_header';

export class WebhookSignatureError extends Error {
  readonly code: WebhookErrorCode;
  constructor(code: WebhookErrorCode) {
    super(`webhook signature: ${code}`);
    this.name = 'WebhookSignatureError';
    this.code = code;
  }
}
