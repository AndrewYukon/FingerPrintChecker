/** True when value is JSON-able: string, finite number, boolean, null, arrays, plain objects. */
export function isJsonable(value: unknown, seen: Set<object> = new Set()): boolean {
  if (value === null) return true;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return true;
    case 'number':
      return Number.isFinite(value);
    case 'object':
      break;
    default:
      return false;
  }
  const obj = value as object;
  if (seen.has(obj)) return false;
  const next = new Set(seen).add(obj);
  if (Array.isArray(obj)) return obj.every((v) => isJsonable(v, next));
  const proto = Object.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(obj).length > 0) return false;
  return Object.values(obj).every((v) => isJsonable(v, next));
}
