// Entry point for `fpchecker`: parses arguments, enforces the key rules, runs one command, returns the exit code.
// 0 ok; 1 the server refused or was unreachable; 2 usage error (bad arguments, no key, a key on the command line).
import { parseArgs } from 'node:util';
import { assertApiUrl, createClient, DEFAULT_API_URL, FpcApiError, FpcNetworkError } from '../client.js';
import { formatHuman, formatJson } from '../format.js';
import { InputError } from '../ids.js';
import { runMcp } from '../mcp.js';
import { checkArgs, COMMANDS, type Opts } from './table.js';

export interface RunDeps {
  env: Record<string, string | undefined>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  fetch?: typeof fetch;
}

const KEY_ENV = 'FPCHECKER_MANAGEMENT_KEY';

const OPTIONS = {
  json: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  'allow-writes': { type: 'boolean' },
  name: { type: 'string' },
  key: { type: 'string' },
  limit: { type: 'string' },
  since: { type: 'string' },
  'visitor-id': { type: 'string' },
  cursor: { type: 'string' },
  file: { type: 'string' },
  event: { type: 'string' },
} as const;

export function helpText(): string {
  return [
    'fpchecker: manage FingerPrint Checker projects from a terminal or an AI assistant',
    '',
    'Usage: fpchecker [--json] <command>',
    '',
    ...COMMANDS.map((c) => `  ${c.usage}`),
    '  mcp [--allow-writes]      start the local MCP server on stdio (read-only unless --allow-writes)',
    '',
    `Environment: ${KEY_ENV} (required), FPCHECKER_API_URL (default ${DEFAULT_API_URL}).`,
    'The key is never accepted as an argument.',
    '',
  ].join('\n');
}

// A key on the command line lands in shell history and process listings, so any argument that looks like one is refused.
const looksLikeKey = (a: string): boolean => a.startsWith('mk_') || a.includes('=mk_');

export async function run(argv: string[], deps: RunDeps): Promise<number> {
  if (argv.some(looksLikeKey)) {
    deps.stderr(`error: refusing an argument that looks like a management key. Set ${KEY_ENV} in the environment instead.\n`);
    return 2;
  }
  try {
    const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
    if (values.help || positionals.length === 0) {
      (values.help ? deps.stdout : deps.stderr)(helpText());
      return values.help ? 0 : 2;
    }
    const isMcp = positionals[0] === 'mcp';
    const cmd = isMcp ? undefined : COMMANDS.find((c) => c.words.every((w, i) => positionals[i] === w));
    if (!isMcp && !cmd) throw new InputError(`unknown command: ${positionals.slice(0, 2).join(' ')} (try --help)`);
    const args = positionals.slice(isMcp ? 1 : (cmd?.words.length ?? 0));
    if (args.length !== (isMcp ? 0 : cmd!.args)) throw new InputError(cmd ? `usage: fpchecker ${cmd.usage}` : 'usage: fpchecker mcp [--allow-writes]');
    if (cmd) checkArgs(cmd, args);

    const key = (deps.env[KEY_ENV] ?? '').trim();
    if (key === '') {
      deps.stderr(`error: ${KEY_ENV} is not set. Create a management key in the console and export it.\n`);
      return 2;
    }
    const apiUrl = deps.env.FPCHECKER_API_URL?.trim() || DEFAULT_API_URL;
    assertApiUrl(apiUrl);
    const client = createClient({ apiUrl, key, fetch: deps.fetch });
    if (isMcp) {
      await runMcp(client, { allowWrites: values['allow-writes'] === true });
      return 0;
    }
    const body = await cmd!.run(client, args, values as Opts);
    deps.stdout(values.json ? formatJson(body) : formatHuman(body));
    return 0;
  } catch (err) {
    if (err instanceof InputError) {
      deps.stderr(`error: ${err.message}\n`);
      return 2;
    }
    if (err instanceof FpcApiError) {
      deps.stderr(`error: ${err.message}\n`);
      return 1;
    }
    if (err instanceof FpcNetworkError) {
      deps.stderr(`error: ${err.message}\n`);
      return 1;
    }
    // parseArgs usage errors (unknown or malformed options) carry no user secrets: mk_ values were refused above.
    if (err instanceof Error && 'code' in err && String((err as { code: unknown }).code).startsWith('ERR_PARSE_ARGS')) {
      deps.stderr(`error: ${err.message}\n`);
      return 2;
    }
    deps.stderr('error: unexpected failure\n');
    return 1;
  }
}
