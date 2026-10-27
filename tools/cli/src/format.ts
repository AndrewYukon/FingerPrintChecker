// Human-readable output. `--json` bypasses this and prints the server body.
type Row = Record<string, unknown>;

const isRow = (v: unknown): v is Row => typeof v === 'object' && v !== null && !Array.isArray(v);
const scalar = (v: unknown): boolean => v === null || ['string', 'number', 'boolean'].includes(typeof v);
const cell = (v: unknown): string => (v === null || v === undefined ? '' : String(v)).replace(/\s+/g, ' ').slice(0, 48);

function table(rows: Row[]): string {
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r).filter((k) => scalar(r[k]))))].slice(0, 7);
  if (cols.length === 0) return JSON.stringify(rows, null, 2);
  const width = cols.map((c) => Math.max(c.length, ...rows.map((r) => cell(r[c]).length)));
  const line = (cells: string[]): string => cells.map((s, i) => s.padEnd(width[i] ?? 0)).join('  ').trimEnd();
  return [line(cols), line(width.map((w) => '-'.repeat(w))), ...rows.map((r) => line(cols.map((c) => cell(r[c]))))].join('\n');
}

export function formatJson(body: unknown): string {
  return `${JSON.stringify(body, null, 2)}\n`;
}

export function formatHuman(body: Row): string {
  const lists = Object.entries(body).filter(([, v]) => Array.isArray(v) && v.length > 0 && v.every(isRow));
  if (lists.length === 1) {
    const [name, rows] = lists[0] as [string, Row[]];
    const rest = Object.entries(body).filter(([k, v]) => k !== name && k !== 'ok' && scalar(v));
    const head = rest.map(([k, v]) => `${k}: ${cell(v)}`);
    return `${[...head, table(rows)].join('\n')}\n`;
  }
  return formatJson(body);
}
