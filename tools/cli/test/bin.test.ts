import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { startFake, type Fake } from './fake-server.js';

const root = fileURLToPath(new URL('..', import.meta.url));
let fake: Fake;
beforeAll(async () => {
  // The test must exercise the real build output, and CI runs tests before the build step.
  execFileSync(process.execPath, [`${root}node_modules/typescript/bin/tsc`, '-p', `${root}tsconfig.json`], { cwd: root });
  fake = await startFake();
}, 60_000);
afterAll(async () => {
  await fake.close();
});

it('dist/bin.js mcp: initialize, tools/list over stdio, exits 0 when stdin closes', async () => {
  const child = spawn(process.execPath, [`${root}dist/bin.js`, 'mcp'], {
    env: { ...process.env, FPCHECKER_MANAGEMENT_KEY: 'mk_' + 'c'.repeat(43), FPCHECKER_API_URL: fake.url },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const lines: Array<{ id?: number; result?: { tools?: Array<{ name: string }> } }> = [];
  let buf = '';
  child.stdout.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      lines.push(JSON.parse(buf.slice(0, i)));
      buf = buf.slice(i + 1);
    }
  });
  const exited = new Promise<number | null>((resolve) => child.on('exit', (c) => resolve(c)));
  const send = (m: unknown) => child.stdin.write(`${JSON.stringify(m)}\n`);
  const until = async (id: number) => {
    for (let n = 0; n < 200 && !lines.some((l) => l.id === id); n++) await new Promise((r) => setTimeout(r, 25));
    return lines.find((l) => l.id === id);
  };
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
  expect(await until(1)).toBeDefined();
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const list = await until(2);
  expect(list?.result?.tools?.map((t) => t.name).sort()).toEqual(
    ['get_event', 'get_project', 'get_ruleset', 'get_usage', 'get_visitor', 'list_audit', 'list_projects', 'list_webhooks', 'search_events', 'test_ruleset'],
  );
  child.stdin.end();
  const code = await Promise.race([exited, new Promise<string>((r) => setTimeout(() => r('timeout'), 5000))]);
  if (code === 'timeout') child.kill();
  expect(code).toBe(0);
}, 30_000);
