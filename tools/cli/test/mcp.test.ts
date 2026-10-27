import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createClient } from '../src/client.js';
import { createMcpServer } from '../src/mcp.js';
import { startFake, type Fake } from './fake-server.js';

const KEY = 'mk_' + 'B'.repeat(43);
const PID = 'prj_0123456789ab';
const EVT = 'ev_0123456789ABCDEFGHJK';
const B = '/v1/management';
const WRITE_TOOLS = ['update_ruleset', 'create_environment', 'rotate_key'];
const READ_TOOLS = ['list_projects', 'get_project', 'get_usage', 'search_events', 'get_event', 'get_visitor', 'get_ruleset', 'test_ruleset', 'list_webhooks', 'list_audit'];

let fake: Fake;
beforeAll(async () => {
  fake = await startFake();
});
afterAll(async () => {
  await fake.close();
});
beforeEach(() => {
  fake.seen.length = 0;
});

async function connect(allowWrites: boolean) {
  const server = createMcpServer(createClient({ apiUrl: fake.url, key: KEY }), { allowWrites });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const text = (r: unknown): string => ((r as { content: Array<{ text: string }> }).content[0] as { text: string }).text;

describe('tool registration', () => {
  it('is read-only by default', async () => {
    const names = (await (await connect(false)).listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual([...READ_TOOLS].sort());
    for (const w of WRITE_TOOLS) expect(names).not.toContain(w);
  });

  it('--allow-writes adds exactly the three write tools', async () => {
    const names = (await (await connect(true)).listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual([...READ_TOOLS, ...WRITE_TOOLS].sort());
  });

  it('a write tool is unknown without --allow-writes', async () => {
    const c = await connect(false);
    const r = await c.callTool({ name: 'rotate_key', arguments: { project_id: PID, key: 'secret' } }).catch((e: unknown) => e);
    const failed = r instanceof Error || (r as { isError?: boolean }).isError === true;
    expect(failed).toBe(true);
    expect(fake.seen).toHaveLength(0);
  });
});

const ruleset = { ifVersion: 1, enabled: true, rules: [] };
const calls: Array<{ tool: string; args: Record<string, unknown>; method: string; path: string; body?: unknown; writes?: true }> = [
  { tool: 'list_projects', args: {}, method: 'GET', path: `${B}/projects` },
  { tool: 'get_project', args: { project_id: PID }, method: 'GET', path: `${B}/projects/${PID}` },
  { tool: 'get_usage', args: {}, method: 'GET', path: `${B}/usage` },
  { tool: 'search_events', args: { project_id: PID, visitor_id: 'v_1', limit: 10, since: '2026-10-01T00:00:00Z' }, method: 'GET', path: `${B}/projects/${PID}/events?visitorId=v_1&limit=10&start=2026-10-01T00%3A00%3A00Z` },
  { tool: 'search_events', args: { project_id: PID }, method: 'GET', path: `${B}/projects/${PID}/events` },
  { tool: 'get_event', args: { project_id: PID, event_id: EVT }, method: 'GET', path: `${B}/projects/${PID}/events/${EVT}` },
  { tool: 'get_visitor', args: { project_id: PID, visitor_id: 'v_1' }, method: 'GET', path: `${B}/projects/${PID}/visitors/v_1` },
  { tool: 'get_ruleset', args: { project_id: PID }, method: 'GET', path: `${B}/projects/${PID}/ruleset` },
  { tool: 'test_ruleset', args: { project_id: PID, event_id: EVT, ruleset }, method: 'POST', path: `${B}/projects/${PID}/ruleset/test`, body: { eventId: EVT, ruleset } },
  { tool: 'list_webhooks', args: { project_id: PID }, method: 'GET', path: `${B}/projects/${PID}/webhooks` },
  { tool: 'list_audit', args: { limit: 5 }, method: 'GET', path: `${B}/audit?limit=5` },
  { tool: 'update_ruleset', args: { project_id: PID, ruleset }, method: 'PUT', path: `${B}/projects/${PID}/ruleset`, body: ruleset, writes: true },
  { tool: 'create_environment', args: { project_id: PID, name: 'staging' }, method: 'POST', path: `${B}/projects/${PID}/environments`, body: { name: 'staging' }, writes: true },
  { tool: 'rotate_key', args: { project_id: PID, key: 'publishable' }, method: 'POST', path: `${B}/projects/${PID}/rotate`, body: { key: 'publishable' }, writes: true },
];

describe('tools call the right route and return server JSON verbatim', () => {
  for (const c of calls) {
    it(`${c.tool} ${JSON.stringify(c.args).slice(0, 40)}`, async () => {
      const client = await connect(true);
      const body = { ok: true, marker: c.tool, nested: { list: [1, { a: 'b' }], big: 12345678901 } };
      fake.reply(200, body);
      const r = await client.callTool({ name: c.tool, arguments: c.args });
      expect((r as { isError?: boolean }).isError).not.toBe(true);
      expect(fake.seen).toEqual([{ method: c.method, path: c.path, authorization: `Bearer ${KEY}`, body: c.body }]);
      expect(JSON.parse(text(r))).toEqual(body);
    });
  }

  it('a server error comes back as a tool error carrying the server JSON, without the key', async () => {
    const client = await connect(true);
    fake.reply(403, { ok: false, error: 'insufficient_scope', echo: KEY });
    const r = await client.callTool({ name: 'rotate_key', arguments: { project_id: PID, key: 'secret' } });
    expect((r as { isError?: boolean }).isError).toBe(true);
    expect(text(r)).toContain('insufficient_scope');
    expect(text(r)).not.toContain(KEY);
  });
});

describe('input schemas validate ids', () => {
  const bad: Array<[string, Record<string, unknown>]> = [
    ['get_project', { project_id: 'abc' }],
    ['get_project', { project_id: '../usage' }],
    ['get_project', { project_id: 'prj_0123456789ab/../x' }],
    ['search_events', { project_id: 'prj_xyz' }],
    ['search_events', { project_id: PID, limit: 0 }],
    ['search_events', { project_id: PID, limit: 101 }],
    ['get_event', { project_id: PID, event_id: 'nope' }],
    ['get_visitor', { project_id: PID, visitor_id: 'a/b' }],
    ['get_visitor', { project_id: PID, visitor_id: '' }],
    ['list_audit', { limit: 101 }],
    ['create_environment', { project_id: PID, name: 'Production!' }],
    ['rotate_key', { project_id: PID, key: 'sealing' }],
    ['update_ruleset', { project_id: 'abc', ruleset }],
    ['test_ruleset', { project_id: PID, event_id: 'bad', ruleset }],
  ];
  for (const [tool, args] of bad) {
    it(`rejects ${tool} ${JSON.stringify(args).slice(0, 50)} before any request`, async () => {
      const client = await connect(true);
      const r = await client.callTool({ name: tool, arguments: args }).catch((e: unknown) => e);
      const failed = r instanceof Error || (r as { isError?: boolean }).isError === true;
      expect(failed).toBe(true);
      expect(fake.seen).toHaveLength(0);
    });
  }
});
