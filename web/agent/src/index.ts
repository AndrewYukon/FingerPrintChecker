import { cacheKey, readCache, validateCache, writeCache } from './cache.js';
import { DEFAULT_ENDPOINT, loadAgentScript } from './load.js';
import {
  FpCheckerAgentError,
  type FpAgent,
  type IdentifyOptions,
  type IdentifyResult,
  type LoadOptions,
} from './types.js';

export * from './types.js';

export async function load(opts: LoadOptions): Promise<FpAgent> {
  if (!opts || typeof opts.publishableKey !== 'string' || opts.publishableKey === '') {
    throw new FpCheckerAgentError('invalid_option', 'publishableKey is required');
  }
  const agent = await loadAgentScript(opts.scriptUrl);
  const baseUrl = opts.endpoint ?? DEFAULT_ENDPOINT;
  const publishableKey = opts.publishableKey;

  return {
    async identify(o: IdentifyOptions): Promise<IdentifyResult> {
      const cache = o.cache === false || o.cache === undefined ? undefined : o.cache;
      if (cache) validateCache(cache);
      const key = cache ? cacheKey(publishableKey, o.linkedId, o.tags) : '';
      if (cache) {
        const hit = readCache(key, cache);
        if (hit) return { ...hit, fromCache: true };
      }
      let body: Record<string, unknown>;
      try {
        body = await agent.identifyV2({
          baseUrl,
          publishableKey,
          intentToken: o.intentToken,
          ...(o.linkedId !== undefined ? { linkedId: o.linkedId } : {}),
          ...(o.tags !== undefined ? { tags: o.tags } : {}),
        });
      } catch (e) {
        const err = e as { name?: string; reason?: unknown; status?: unknown; message?: string };
        if (err?.name === 'IdentifyV2Error') {
          throw new FpCheckerAgentError(
            'identify_failed',
            err.message ?? 'identify failed',
            typeof err.reason === 'string' ? err.reason : undefined,
            typeof err.status === 'number' ? err.status : undefined,
          );
        }
        throw e;
      }
      const eventId = body.eventId;
      if (typeof eventId !== 'string') {
        throw new FpCheckerAgentError('identify_failed', 'server response had no eventId');
      }
      const result: IdentifyResult = { eventId, fromCache: false };
      if (typeof body.attestation === 'string') result.attestation = body.attestation;
      if (typeof body.sealedResult === 'string') result.sealedResult = body.sealedResult;
      if (typeof body.expiresIn === 'number') result.expiresIn = body.expiresIn;
      if (cache) {
        writeCache(key, cache, result.sealedResult === undefined ? { eventId } : { eventId, sealedResult: result.sealedResult });
      }
      return result;
    },
  };
}
