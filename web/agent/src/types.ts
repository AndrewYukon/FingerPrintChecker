export interface LoadOptions {
  publishableKey: string;
  /** API base URL. Default https://api.fpchecker.com */
  endpoint?: string;
  /** Load the agent from this URL via <script src> instead of injecting it inline (strict CSP). */
  scriptUrl?: string;
}

export interface CacheOptions {
  /** 1..3600 */
  ttlSeconds: number;
  storage: 'memory' | 'session' | 'local';
}

export interface IdentifyOptions {
  intentToken: string;
  linkedId?: string;
  tags?: Record<string, unknown>;
  /** Default off. `false` forces a fresh request. */
  cache?: false | CacheOptions;
}

export interface IdentifyResult {
  /** Absent on a cache hit. */
  attestation?: string;
  eventId: string;
  sealedResult?: string;
  /** Absent on a cache hit. */
  expiresIn?: number;
  fromCache: boolean;
}

export interface FpAgent {
  identify(opts: IdentifyOptions): Promise<IdentifyResult>;
}

export type ErrorCode = 'ssr' | 'invalid_option' | 'load_failed' | 'identify_failed';

export class FpCheckerAgentError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    /** Server reason from IdentifyV2Error, if any. */
    readonly reason?: string,
    /** HTTP status from IdentifyV2Error, if any. */
    readonly status?: number,
  ) {
    super(message);
    this.name = 'FpCheckerAgentError';
  }
}
