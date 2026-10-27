// The command table: one entry per `fpchecker <group> <verb>`. `run` gets the validated positionals and options.
import { readFileSync } from 'node:fs';
import type { Client, Json } from '../client.js';
import * as ids from '../ids.js';

export interface Opts {
  name?: string;
  key?: string;
  limit?: string;
  since?: string;
  'visitor-id'?: string;
  cursor?: string;
  file?: string;
  event?: string;
}

export interface Command {
  words: [string, string] | [string];
  usage: string;
  /** Number of positional arguments after the command words. */
  args: number;
  run: (c: Client, args: string[], o: Opts) => Promise<Json>;
}

const need = (v: string | undefined, flag: string): string => {
  if (v === undefined || v === '') throw new ids.InputError(`missing ${flag}`);
  return v;
};

function readJsonFile(path: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new ids.InputError(`cannot read file: ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ids.InputError(`not valid JSON: ${path}`);
  }
}

const lim = (o: Opts): number | undefined => (o.limit === undefined ? undefined : ids.limit(o.limit));

export const COMMANDS: readonly Command[] = [
  { words: ['projects', 'list'], usage: 'projects list', args: 0, run: (c) => c.listProjects() },
  { words: ['projects', 'get'], usage: 'projects get <projectId>', args: 1, run: (c, [p]) => c.getProject(p!) },
  { words: ['projects', 'create'], usage: 'projects create --name <name>', args: 0, run: (c, _a, o) => c.createProject(need(o.name, '--name')) },
  { words: ['environments', 'create'], usage: 'environments create <projectId> --name <env>', args: 1, run: (c, [p], o) => c.createEnvironment(p!, need(o.name, '--name')) },
  { words: ['keys', 'rotate'], usage: 'keys rotate <projectId> --key secret|publishable', args: 1, run: (c, [p], o) => c.rotateKey(p!, ids.keyKind(need(o.key, '--key'))) },
  {
    words: ['events', 'list'],
    usage: 'events list <projectId> [--visitor-id <id>] [--limit <n>] [--since <time>] [--cursor <c>]',
    args: 1,
    run: (c, [p], o) => c.searchEvents(p!, { visitorId: o['visitor-id'], limit: lim(o), since: o.since, cursor: o.cursor }),
  },
  { words: ['events', 'get'], usage: 'events get <projectId> <eventId>', args: 2, run: (c, [p, e]) => c.getEvent(p!, e!) },
  { words: ['visitors', 'get'], usage: 'visitors get <projectId> <visitorId>', args: 2, run: (c, [p, v]) => c.getVisitor(p!, v!) },
  { words: ['ruleset', 'get'], usage: 'ruleset get <projectId>', args: 1, run: (c, [p]) => c.getRuleset(p!) },
  { words: ['ruleset', 'set'], usage: 'ruleset set <projectId> --file <ruleset.json>', args: 1, run: (c, [p], o) => c.setRuleset(p!, readJsonFile(need(o.file, '--file'))) },
  {
    words: ['ruleset', 'test'],
    usage: 'ruleset test <projectId> --event <eventId> [--file <ruleset.json>]',
    args: 1,
    run: async (c, [p], o) => {
      const eventId = ids.eventId(need(o.event, '--event'));
      let draft: unknown;
      if (o.file !== undefined) draft = readJsonFile(o.file);
      else draft = (await c.getRuleset(p!)).ruleset;
      return c.testRuleset(p!, eventId, draft);
    },
  },
  { words: ['webhooks', 'list'], usage: 'webhooks list <projectId>', args: 1, run: (c, [p]) => c.listWebhooks(p!) },
  { words: ['usage'], usage: 'usage', args: 0, run: (c) => c.getUsage() },
  { words: ['audit'], usage: 'audit [--limit <n>] [--cursor <c>]', args: 0, run: (c, _a, o) => c.listAudit({ limit: lim(o), cursor: o.cursor }) },
];

/** Validate the positional ids of a command before anything is sent. */
export function checkArgs(cmd: Command, args: string[]): void {
  const [first, second] = args;
  switch (cmd.words.join(' ')) {
    case 'projects get':
    case 'environments create':
    case 'keys rotate':
    case 'events list':
    case 'events get':
    case 'visitors get':
    case 'ruleset get':
    case 'ruleset set':
    case 'ruleset test':
    case 'webhooks list':
      ids.projectId(first!);
  }
  if (cmd.words.join(' ') === 'events get') ids.eventId(second!);
  if (cmd.words.join(' ') === 'visitors get') ids.visitorId(second!);
}
