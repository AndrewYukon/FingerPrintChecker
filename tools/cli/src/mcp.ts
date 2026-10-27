// Local stdio MCP server over the Management API. Read tools always; write tools only with --allow-writes.
// Tool results are the server's JSON, verbatim, as text: nothing is summarized or trimmed before the model sees it.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { FpcApiError, FpcNetworkError, type Client, type Json } from './client.js';
import { ENV_NAME_RE, EVENT_ID_RE, KEY_KINDS, MAX_LIMIT, PROJECT_ID_RE, VISITOR_ID_RE } from './ids.js';

export interface McpOptions {
  allowWrites: boolean;
}

const project_id = z.string().regex(PROJECT_ID_RE, 'expected prj_ followed by 12 hex characters');
const event_id = z.string().regex(EVENT_ID_RE, 'expected ev_ followed by 20 characters');
const visitor_id = z.string().regex(VISITOR_ID_RE, 'expected 1 to 80 letters, digits, - or _');
const limit = z.number().int().min(1).max(MAX_LIMIT);
const ruleset = z.record(z.string(), z.unknown());

type Result = { content: Array<{ type: 'text'; text: string }>; isError?: true };
const text = (t: string, isError = false): Result => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError: true as const } : {}) });

async function reply(p: Promise<Json>): Promise<Result> {
  try {
    return text(JSON.stringify(await p, null, 2));
  } catch (err) {
    if (err instanceof FpcApiError) return text(err.body === undefined ? err.message : JSON.stringify(err.body, null, 2), true);
    if (err instanceof FpcNetworkError) return text(err.message, true);
    return text('unexpected failure', true);
  }
}

export function createMcpServer(client: Client, opts: McpOptions): McpServer {
  const server = new McpServer({ name: 'fpchecker', version: '0.1.0' });
  const read = { readOnlyHint: true } as const;

  server.registerTool('list_projects', { description: 'List the projects (and their environments) on the account.', annotations: read }, () => reply(client.listProjects()));
  server.registerTool('get_project', { description: 'Get one project.', inputSchema: { project_id }, annotations: read }, ({ project_id }) => reply(client.getProject(project_id)));
  server.registerTool('get_usage', { description: 'Get the account usage and credit balance.', annotations: read }, () => reply(client.getUsage()));
  server.registerTool(
    'search_events',
    {
      description: 'Search a project\'s identification events, newest first. Filter by visitor and start time; page with the returned cursor.',
      inputSchema: { project_id, visitor_id: visitor_id.optional(), limit: limit.optional(), since: z.string().min(1).max(40).optional().describe('Start of the window, ISO 8601'), cursor: z.string().min(1).max(512).optional() },
      annotations: read,
    },
    (a) => reply(client.searchEvents(a.project_id, { visitorId: a.visitor_id, limit: a.limit, since: a.since, cursor: a.cursor })),
  );
  server.registerTool('get_event', { description: 'Get one event with all its recorded signals.', inputSchema: { project_id, event_id }, annotations: read }, (a) => reply(client.getEvent(a.project_id, a.event_id)));
  server.registerTool('get_visitor', { description: 'Get a visitor summary.', inputSchema: { project_id, visitor_id }, annotations: read }, (a) => reply(client.getVisitor(a.project_id, a.visitor_id)));
  server.registerTool('get_ruleset', { description: 'Get the project\'s saved ruleset and its version.', inputSchema: { project_id }, annotations: read }, (a) => reply(client.getRuleset(a.project_id)));
  server.registerTool(
    'test_ruleset',
    { description: 'Dry-run a draft ruleset against a stored event. Changes nothing.', inputSchema: { project_id, event_id, ruleset }, annotations: read },
    (a) => reply(client.testRuleset(a.project_id, a.event_id, a.ruleset)),
  );
  server.registerTool('list_webhooks', { description: 'List the project\'s webhooks.', inputSchema: { project_id }, annotations: read }, (a) => reply(client.listWebhooks(a.project_id)));
  server.registerTool(
    'list_audit',
    { description: 'List the account audit log, newest first.', inputSchema: { limit: limit.optional(), cursor: z.string().min(1).max(512).optional() }, annotations: read },
    (a) => reply(client.listAudit({ limit: a.limit, cursor: a.cursor })),
  );

  if (opts.allowWrites) {
    server.registerTool(
      'update_ruleset',
      { description: 'Save a ruleset. The body carries ifVersion (the version it is based on); a stale version is refused.', inputSchema: { project_id, ruleset }, annotations: { destructiveHint: true } },
      (a) => reply(client.setRuleset(a.project_id, a.ruleset)),
    );
    server.registerTool(
      'create_environment',
      { description: 'Create a child environment of a project.', inputSchema: { project_id, name: z.string().regex(ENV_NAME_RE, 'lowercase letters, digits and dashes') }, annotations: { destructiveHint: false } },
      (a) => reply(client.createEnvironment(a.project_id, a.name)),
    );
    server.registerTool(
      'rotate_key',
      { description: 'Rotate a project key. The old key stops working and the new one is returned once.', inputSchema: { project_id, key: z.enum(KEY_KINDS) }, annotations: { destructiveHint: true } },
      (a) => reply(client.rotateKey(a.project_id, a.key)),
    );
  }
  return server;
}

/** Serve on stdio until the client disconnects. Nothing else may write to stdout while this runs. */
export async function runMcp(client: Client, opts: McpOptions): Promise<void> {
  const server = createMcpServer(client, opts);
  const closed = new Promise<void>((resolve) => {
    server.server.onclose = () => resolve();
    // The stdio transport does not report a closed stdin, so a client that exits would leave this process hanging.
    process.stdin.once('end', () => resolve());
  });
  await server.connect(new StdioServerTransport());
  await closed;
}
