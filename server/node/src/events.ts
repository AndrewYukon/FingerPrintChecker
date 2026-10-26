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
  return {
    ...body,
    data: {
      ...data,
      visitorId: data.visitorId,
      ...(typeof data.proxied === 'boolean' ? { proxied: data.proxied } : {}),
      ...(ruleAction !== undefined ? { ruleAction } : {}),
    },
  } as WebhookEvent;
}

/** Narrow an eligibility response; `ruleId` is surfaced only when it is a string. */
export function parseEligibilityAnswer(body: unknown): EligibilityAnswer {
  if (!isObject(body)) throw new TypeError('parseEligibilityAnswer: not an object');
  const { ruleId, ...rest } = body;
  return { ...rest, ok: body.ok === true, ...(typeof ruleId === 'string' ? { ruleId } : {}) };
}
