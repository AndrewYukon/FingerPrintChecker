// Id shapes the Management API accepts. Checked before a request is built so a bad id can never
// reach the URL path (no "../", no extra segments).
export const PROJECT_ID_RE = /^prj_[0-9a-f]{12}$/;
export const EVENT_ID_RE = /^ev_[0-9A-HJKMNP-TV-Z]{20}$/;
export const VISITOR_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;
export const ENV_NAME_RE = /^[a-z][a-z0-9-]{0,19}$/;
export const KEY_KINDS = ['secret', 'publishable'] as const;
export type KeyKind = (typeof KEY_KINDS)[number];
export const MAX_LIMIT = 100;

export class InputError extends Error {}

function check(re: RegExp, what: string) {
  return (v: string): string => {
    if (!re.test(v)) throw new InputError(`invalid ${what}: ${JSON.stringify(v.slice(0, 40))}`);
    return v;
  };
}

export const projectId = check(PROJECT_ID_RE, 'project id (expected prj_ followed by 12 hex characters)');
export const eventId = check(EVENT_ID_RE, 'event id (expected ev_ followed by 20 characters)');
export const visitorId = check(VISITOR_ID_RE, 'visitor id');
export const envName = check(ENV_NAME_RE, 'environment name (lowercase letters, digits and dashes, starting with a letter, up to 20)');

export function keyKind(v: string): KeyKind {
  if (v !== 'secret' && v !== 'publishable') throw new InputError('invalid --key: expected "secret" or "publishable"');
  return v;
}

export function limit(v: string | number): number {
  const n = typeof v === 'number' ? v : /^\d{1,6}$/.test(v) ? Number(v) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > MAX_LIMIT) throw new InputError(`invalid limit: expected 1 to ${MAX_LIMIT}`);
  return n;
}
