import type { BotCategory, BotIdentity, BotInfo, BotResult } from './bot.js';

/** Rule action types. The server may add values; an unknown one is kept as-is (treat it as `none`). */
export type RuleActionType = 'allow' | 'human_check' | 'deny' | 'none' | (string & {});

/** What the project's ruleset decided for an event. */
export interface RuleAction {
  type: RuleActionType;
  /** The matching rule; absent when `type` is `none`. */
  ruleId?: string;
  ruleName?: string;
  rulesetVersion: number;
}

/** How the VPN signal was reached. `os_vpn` is the device reporting an active VPN. Open: ignore a value you do not know. */
export type VpnMethod = 'timezone_mismatch' | 'ip_range' | 'relay' | 'os_vpn' | (string & {});

/**
 * Device-state signals of an android, ios or macos event. Each flag has three states:
 * `true` = detected, `false` = checked and nothing found, `null` = not checked
 * (old SDK, probes switched off, not supported on this platform). Not a guarantee either way.
 */
export interface MobileSignals {
  emulator: boolean | null;
  attested: boolean | null;
  integrity: 'strong' | 'basic' | 'failed' | null;
  rooted: boolean | null;
  hooked: boolean | null;
  debugger: boolean | null;
  developerMode: boolean | null;
  mitm: boolean | null;
  vpn: boolean | null;
  locationSpoofed: boolean | null;
  clonedApp: boolean | null;
  /** Reserved: the SDK does not report factory resets, so this is currently always null. */
  factoryResetAt: string | null;
}

/**
 * `signals.bot`. Events stored before server 0.48.0 are version 1: no `good` result and no `info`.
 * `info` is set when the request named an entry of the Bot directory.
 */
export interface BotSignals {
  /** `null` when not checked. */
  result: BotResult | null;
  types: string[];
  info?: BotInfo | null;
  [k: string]: unknown;
}

/** Event signals this SDK types; every other signal is kept untyped. */
export interface EventSignals {
  /** 1 for events stored before server 0.48.0, 2 since. */
  version?: 1 | 2;
  bot?: BotSignals;
  vpn?: { result: boolean | null; methods: VpnMethod[] };
  /** Null for web events. */
  mobile?: MobileSignals | null;
  [k: string]: unknown;
}

/** Filters of `searchEvents`. The signal filters match the event's `signals`; unknown keys are passed through. */
export interface SearchEventsQuery {
  rooted?: boolean;
  hooked?: boolean;
  emulator?: boolean;
  mitm?: boolean;
  locationSpoofed?: boolean;
  clonedApp?: boolean;
  /** Exact match on `signals.bot.result`. */
  botResult?: BotResult;
  botCategory?: BotCategory;
  botIdentity?: BotIdentity;
  /** Id of a Bot directory entry, e.g. `googlebot`. */
  botId?: string;
  [k: string]: string | number | boolean | undefined | null;
}

const WIRE_NAMES: Record<string, string> = {
  botResult: 'bot_result',
  botCategory: 'bot_category',
  botIdentity: 'bot_identity',
  botId: 'bot_id',
};

/** Map the camelCase bot filters to the API's query names; every other key passes through. */
export function toWireQuery(q: SearchEventsQuery): SearchEventsQuery {
  return Object.fromEntries(Object.entries(q).map(([k, v]) => [WIRE_NAMES[k] ?? k, v]));
}

/** An event as delivered in a webhook body. Unknown fields are kept. */
export interface WebhookEvent {
  id?: string;
  type?: string;
  data: {
    visitorId: string;
    /** True when the request came through the project's Cloudflare proxy. Missing in payloads queued before server 0.45.0. */
    proxied?: boolean;
    /** Null when the ruleset is disabled; missing in payloads queued before server 0.45.0. */
    ruleAction?: RuleAction | null;
    /** Missing in payloads queued before server 0.43.0. */
    signals?: EventSignals;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

/** Answer of `checkEligibility`. Reasons are open strings: new values may be added. */
export interface EligibilityAnswer {
  ok: boolean;
  eligible?: boolean;
  action?: string;
  reason?: string;
  /** Present only when a rule decided the answer or an allow rule applied. */
  ruleId?: string;
  [k: string]: unknown;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseRuleAction(v: unknown): RuleAction | null | undefined {
  if (v === undefined) return undefined;
  if (v === null) return null;
  if (!isObject(v) || typeof v.type !== 'string') return null;
  return {
    type: v.type,
    ...(typeof v.ruleId === 'string' ? { ruleId: v.ruleId } : {}),
    ...(typeof v.ruleName === 'string' ? { ruleName: v.ruleName } : {}),
    rulesetVersion: typeof v.rulesetVersion === 'number' ? v.rulesetVersion : 0,
  };
}

const tri = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
const INTEGRITY = ['strong', 'basic', 'failed'] as const;

function parseMobile(v: unknown): MobileSignals | null | undefined {
  if (v === undefined) return undefined;
  if (!isObject(v)) return null;
  const integrity = INTEGRITY.find((x) => x === v.integrity) ?? null;
  return {
    emulator: tri(v.emulator),
    attested: tri(v.attested),
    integrity,
    rooted: tri(v.rooted),
    hooked: tri(v.hooked),
    debugger: tri(v.debugger),
    developerMode: tri(v.developerMode),
    mitm: tri(v.mitm),
    vpn: tri(v.vpn),
    locationSpoofed: tri(v.locationSpoofed),
    clonedApp: tri(v.clonedApp),
    factoryResetAt: typeof v.factoryResetAt === 'string' ? v.factoryResetAt : null,
  };
}

function parseVpn(v: unknown): EventSignals['vpn'] | undefined {
  if (!isObject(v)) return undefined;
  const methods = Array.isArray(v.methods) ? { methods: v.methods.filter((m): m is VpnMethod => typeof m === 'string') } : {};
  return { ...v, ...('result' in v ? { result: tri(v.result) } : {}), ...methods } as EventSignals['vpn'];
}

function parseSignals(v: unknown): EventSignals | undefined {
  if (!isObject(v)) return undefined;
  const mobile = parseMobile(v.mobile);
  const vpn = parseVpn(v.vpn);
  return { ...v, ...(vpn !== undefined ? { vpn } : {}), ...(mobile !== undefined ? { mobile } : {}) } as EventSignals;
}

/**
 * Parse a webhook body (verify its signature first). `proxied` and `ruleAction`
 * are optional: older payloads lack them. Unknown rule types do not throw.
 */
export function parseWebhookEvent(rawBody: string | Uint8Array): WebhookEvent {
  const text = typeof rawBody === 'string' ? rawBody : Buffer.from(rawBody).toString('utf8');
  const body: unknown = JSON.parse(text);
  if (!isObject(body) || !isObject(body.data) || typeof body.data.visitorId !== 'string')
    throw new TypeError('parseWebhookEvent: not a webhook event');
  const { data } = body;
  const ruleAction = parseRuleAction(data.ruleAction);
  const signals = parseSignals(data.signals);
  return {
    ...body,
    data: {
      ...data,
      visitorId: data.visitorId,
      ...(typeof data.proxied === 'boolean' ? { proxied: data.proxied } : {}),
      ...(ruleAction !== undefined ? { ruleAction } : {}),
      ...(signals !== undefined ? { signals } : {}),
    },
  } as WebhookEvent;
}

/** Narrow an eligibility response; `ruleId` is surfaced only when it is a string. */
export function parseEligibilityAnswer(body: unknown): EligibilityAnswer {
  if (!isObject(body)) throw new TypeError('parseEligibilityAnswer: not an object');
  const { ruleId, ...rest } = body;
  return { ...rest, ok: body.ok === true, ...(typeof ruleId === 'string' ? { ruleId } : {}) };
}
