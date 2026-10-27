import { NativeModules } from 'react-native';
import { isJsonable } from './tags';
import type { FpConfig, FpFailure, FpIdentifyOptions, FpIdentifyResult } from './types';

export type { FpConfig, FpFailure, FpIdentifyOptions, FpIdentifyResult, FpSuccess } from './types';

type NativeModule = { identify(args: Record<string, unknown>): Promise<unknown> };

const fail = (reason: string, httpStatus = 0): FpFailure => ({ ok: false, reason, httpStatus });

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const optStr = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const optNum = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

function cleanConfig(config: FpConfig): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(config).filter(([, v]) => v !== undefined && v !== null),
  );
}

function mapReply(reply: unknown): FpIdentifyResult {
  if (!isRecord(reply) || typeof reply.ok !== 'boolean') return fail('bridge_error');
  if (!reply.ok) {
    if (typeof reply.reason !== 'string') return fail('bridge_error');
    return fail(reply.reason, optNum(reply.httpStatus) ?? 0);
  }
  if (typeof reply.attestation !== 'string' || reply.attestation === '') return fail('bridge_error');
  if (reply.visitorId != null && typeof reply.visitorId !== 'string') {
    return fail('bridge_error');
  }
  return {
    ok: true,
    visitorId: optStr(reply.visitorId),
    attestation: reply.attestation,
    eventId: optStr(reply.eventId),
    trustScore: optNum(reply.trustScore),
    identityConfidence: optNum(reply.identityConfidence),
    isNew: typeof reply.isNew === 'boolean' ? reply.isNew : undefined,
    trustDeductions: strList(reply.trustDeductions),
    shadowDeductions: strList(reply.shadowDeductions),
    proofStatus: optStr(reply.proofStatus),
    expiresIn: optNum(reply.expiresIn),
    rulesVersion: optStr(reply.rulesVersion),
    sealedResult: optStr(reply.sealedResult),
    rawJson: optStr(reply.rawJson) ?? '',
  };
}

export class FingerPrintChecker {
  private readonly config: FpConfig;

  constructor(config: FpConfig) {
    this.config = { ...config };
  }

  async identify(intentToken: string, opts: FpIdentifyOptions = {}): Promise<FpIdentifyResult> {
    try {
      if (typeof intentToken !== 'string' || intentToken.length === 0) {
        return fail('bad_intent_token');
      }
      const pk = this.config?.publishableKey;
      if (typeof pk !== 'string' || pk.length === 0) return fail('bad_config');
      const { linkedId, tags } = opts;
      if (tags !== undefined && (!isRecord(tags) || !isJsonable(tags))) return fail('invalid_tags');

      const native = NativeModules.FingerPrintCheckerModule as NativeModule | undefined;
      if (!native || typeof native.identify !== 'function') return fail('not_linked');

      const args: Record<string, unknown> = {
        config: cleanConfig(this.config),
        intentToken,
        ...(linkedId !== undefined ? { linkedId } : {}),
        ...(tags !== undefined ? { tags } : {}),
      };
      return mapReply(await native.identify(args));
    } catch {
      return fail('bridge_error');
    }
  }
}
