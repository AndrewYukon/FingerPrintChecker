import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../src/commands/index.js';
import { startFake, type Fake } from './fake-server.js';

const KEY = 'mk_' + 'A'.repeat(43);
const PID = 'prj_0123456789ab';
const EVT = 'ev_0123456789ABCDEFGHJK';
const B = '/v1/management';

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

async function cli(argv: string[], env: Record<string, string | undefined> = {}) {
  let out = '';
  let err = '';
  const code = await run(argv, {
    env: { FPCHECKER_MANAGEMENT_KEY: KEY, FPCHECKER_API_URL: fake.url, ...env },
    stdout: (s) => (out += s),
    stderr: (s) => (err += s),
  });
  return { code, out, err };
}

const dir = mkdtempSync(join(tmpdir(), 'fpc-cli-'));
const rulesetFile = join(dir, 'ruleset.json');
const ruleset = { ifVersion: 3, enabled: true, rules: [] };
writeFileSync(rulesetFile, JSON.stringify(ruleset));

const cases: Array<{ name: string; argv: string[]; method: string; path: string; body?: unknown }> = [
  { name: 'projects list', argv: ['projects', 'list'], method: 'GET', path: `${B}/projects` },
  { name: 'projects get', argv: ['projects', 'get', PID], method: 'GET', path: `${B}/projects/${PID}` },
  { name: 'projects create', argv: ['projects', 'create', '--name', 'Shop'], method: 'POST', path: `${B}/projects`, body: { name: 'Shop' } },
  { name: 'environments create', argv: ['environments', 'create', PID, '--name', 'staging'], method: 'POST', path: `${B}/projects/${PID}/environments`, body: { name: 'staging' } },
  { name: 'keys rotate', argv: ['keys', 'rotate', PID, '--key', 'secret'], method: 'POST', path: `${B}/projects/${PID}/rotate`, body: { key: 'secret' } },
  { name: 'events list', argv: ['events', 'list', PID, '--visitor-id', 'v_1', '--limit', '5', '--since', '2026-10-01T00:00:00Z'], method: 'GET', path: `${B}/projects/${PID}/events?visitorId=v_1&limit=5&start=2026-10-01T00%3A00%3A00Z` },
  { name: 'events list (no filters)', argv: ['events', 'list', PID], method: 'GET', path: `${B}/projects/${PID}/events` },
  { name: 'events get', argv: ['events', 'get', PID, EVT], method: 'GET', path: `${B}/projects/${PID}/events/${EVT}` },
  { name: 'visitors get', argv: ['visitors', 'get', PID, 'v_1'], method: 'GET', path: `${B}/projects/${PID}/visitors/v_1` },
  { name: 'ruleset get', argv: ['ruleset', 'get', PID], method: 'GET', path: `${B}/projects/${PID}/ruleset` },
  { name: 'ruleset set', argv: ['ruleset', 'set', PID, '--file', rulesetFile], method: 'PUT', path: `${B}/projects/${PID}/ruleset`, body: ruleset },
  { name: 'ruleset test', argv: ['ruleset', 'test', PID, '--event', EVT, '--file', rulesetFile], method: 'POST', path: `${B}/projects/${PID}/ruleset/test`, body: { eventId: EVT, ruleset } },
  { name: 'webhooks list', argv: ['webhooks', 'list', PID], method: 'GET', path: `${B}/projects/${PID}/webhooks` },
  { name: 'usage', argv: ['usage'], method: 'GET', path: `${B}/usage` },
  { name: 'audit', argv: ['audit', '--limit', '7'], method: 'GET', path: `${B}/audit?limit=7` },
  { name: 'audit (default)', argv: ['audit'], method: 'GET', path: `${B}/audit` },
];

describe('commands hit the right route', () => {
  for (const c of cases) {
    it(c.name, async () => {
      const r = await cli(c.argv);
      expect(r.code).toBe(0);
      expect(fake.seen).toEqual([{ method: c.method, path: c.path, authorization: `Bearer ${KEY}`, body: c.body }]);
    });
  }

  it('ruleset test without --file tests the saved ruleset', async () => {
    fake.reply(200, { ok: true, ruleset });
    const r = await cli(['ruleset', 'test', PID, '--event', EVT]);
    expect(r.code).toBe(0);
    expect(fake.seen.map((s) => [s.method, s.path, s.body])).toEqual([
      ['GET', `${B}/projects/${PID}/ruleset`, undefined],
      ['POST', `${B}/projects/${PID}/ruleset/test`, { eventId: EVT, ruleset }],
    ]);
  });
});

describe('output', () => {
  it('--json prints the server body unchanged', async () => {
    const body = { ok: true, projects: [{ id: PID, name: 'Shop', extra: { a: [1, 2] } }] };
    fake.reply(200, body);
    const r = await cli(['--json', 'projects', 'list']);
    expect(JSON.parse(r.out)).toEqual(body);
  });

  it('--json works after the subcommand too', async () => {
    fake.reply(200, { ok: true, usage: { n: 1 } });
    const r = await cli(['usage', '--json']);
    expect(JSON.parse(r.out)).toEqual({ ok: true, usage: { n: 1 } });
  });

  it('default output is a readable table', async () => {
    fake.reply(200, { ok: true, projects: [{ id: PID, name: 'Shop' }, { id: 'prj_ffffffffffff', name: 'Blog' }] });
    const r = await cli(['projects', 'list']);
    expect(r.out).toContain('id');
    expect(r.out).toContain('name');
    expect(r.out).toContain('Shop');
    expect(r.out).toContain('Blog');
    expect(r.out.trimStart().startsWith('{')).toBe(false);
  });

  it('a server error exits 1 with the error code', async () => {
    fake.reply(404, { ok: false, error: 'project_not_found' });
    const r = await cli(['projects', 'get', PID]);
    expect(r.code).toBe(1);
    expect(r.err).toContain('project_not_found');
    expect(r.err).toContain('404');
  });

  it('never prints the key, even when the server echoes it', async () => {
    fake.reply(401, { ok: false, error: `bad key ${KEY}` });
    for (const extra of [[], ['--json']]) {
      fake.reply(401, { ok: false, error: `bad key ${KEY}` });
      const r = await cli([...extra, 'usage']);
      expect(r.code).toBe(1);
      expect(r.out + r.err).not.toContain(KEY);
      expect(r.out + r.err).not.toContain('mk_');
    }
  });

  it('never prints the key when the server is unreachable', async () => {
    const r = await cli(['usage'], { FPCHECKER_API_URL: `http://127.0.0.1:1/${KEY}` });
    expect(r.code).toBe(1);
    expect(r.out + r.err).not.toContain(KEY);
  });
});

describe('key handling', () => {
  it('no key: exit 2 and a hint, no request', async () => {
    const r = await cli(['usage'], { FPCHECKER_MANAGEMENT_KEY: undefined });
    expect(r.code).toBe(2);
    expect(r.err).toContain('FPCHECKER_MANAGEMENT_KEY');
    expect(fake.seen).toHaveLength(0);
  });

  it('empty key counts as no key', async () => {
    const r = await cli(['usage'], { FPCHECKER_MANAGEMENT_KEY: '  ' });
    expect(r.code).toBe(2);
  });

  for (const argv of [
    ['--key', 'mk_x', 'usage'],
    ['usage', '--key=mk_x'],
    ['projects', 'get', 'mk_abc'],
    ['mcp', 'mk_abc'],
    ['--api-key', 'mk_x', 'usage'],
  ]) {
    it(`refuses an mk_ argument: ${argv.join(' ')}`, async () => {
      const r = await cli(argv);
      expect(r.code).toBe(2);
      expect(r.err).not.toContain('mk_x');
      expect(r.err).not.toContain('mk_abc');
      expect(fake.seen).toHaveLength(0);
    });
  }

  it('refuses an mk_ argument even without the env key', async () => {
    const r = await cli(['usage', 'mk_x'], { FPCHECKER_MANAGEMENT_KEY: undefined });
    expect(r.code).toBe(2);
    expect(r.err).toContain('argument');
  });

  it('API URL defaults to api.fpchecker.com', async () => {
    let called = '';
    const { run: runWith } = await import('../src/commands/index.js');
    const code = await runWith(['usage'], {
      env: { FPCHECKER_MANAGEMENT_KEY: KEY },
      stdout: () => {},
      stderr: () => {},
      fetch: (async (u: string | URL) => {
        called = String(u);
        return new Response('{"ok":true}', { status: 200 });
      }) as typeof fetch,
    });
    expect(code).toBe(0);
    expect(called).toBe('https://api.fpchecker.com/v1/management/usage');
  });
});

describe('usage errors', () => {
  for (const argv of [
    [],
    ['nope'],
    ['projects'],
    ['projects', 'get', 'not-an-id'],
    ['projects', 'create'],
    ['keys', 'rotate', PID, '--key', 'sealing'],
    ['events', 'get', PID, 'bad'],
    ['events', 'list', PID, '--limit', 'abc'],
    ['ruleset', 'set', PID],
    ['ruleset', 'set', PID, '--file', '/nonexistent/file.json'],
    ['environments', 'create', PID, '--name', 'Bad Name'],
    ['usage', '--bogus'],
  ]) {
    it(`exit 2 and no request: ${argv.join(' ') || '(none)'}`, async () => {
      const r = await cli(argv);
      expect(r.code).toBe(2);
      expect(r.err.length).toBeGreaterThan(0);
      expect(fake.seen).toHaveLength(0);
    });
  }

  it('--help exits 0 without a key', async () => {
    const r = await cli(['--help'], { FPCHECKER_MANAGEMENT_KEY: undefined });
    expect(r.code).toBe(0);
    expect(r.out).toContain('fpchecker');
  });
});

describe('FPCHECKER_API_URL', () => {
  for (const url of ['http://api.fpchecker.com', 'ftp://127.0.0.1', 'not a url', `http://example.com/${KEY}`]) {
    it(`rejects ${url.replace(KEY, '<key>')}`, async () => {
      const r = await cli(['usage'], { FPCHECKER_API_URL: url });
      expect(r.code).toBe(2);
      expect(r.err).toContain('FPCHECKER_API_URL');
      expect(r.out + r.err).not.toContain(KEY);
      expect(fake.seen).toHaveLength(0);
    });
  }

  it('allows http on loopback', async () => {
    for (const host of ['localhost', '127.0.0.1', '[::1]']) {
      const seen: string[] = [];
      const code = await run(['usage'], {
        env: { FPCHECKER_MANAGEMENT_KEY: KEY, FPCHECKER_API_URL: `http://${host}:9` },
        stdout: () => {},
        stderr: () => {},
        fetch: (async (u: string | URL) => (seen.push(String(u)), new Response('{"ok":true}'))) as typeof fetch,
      });
      expect(code).toBe(0);
      expect(seen).toEqual([`http://${host}:9/v1/management/usage`]);
    }
  });
});
