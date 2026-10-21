// fpchecker CLI identify (Node 18+). Env: FPC_PK, FPC_SEAL, FPC_TENANT, FPC_BASE (default https://api.fpchecker.com), FPC_POW (default 16).
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, release } from 'node:os';
const { FPC_PK: pk, FPC_SEAL: seal, FPC_TENANT: tenant = 'fpchecker', FPC_BASE: base = 'https://api.fpchecker.com', FPC_POW: bits = '16' } = process.env;
const dir = `${homedir()}/.config/${tenant}`, idFile = `${dir}/device-id`;
let randomId; try { randomId = readFileSync(idFile, 'utf8').trim(); } catch { mkdirSync(dir, { recursive: true }); writeFileSync(idFile, (randomId = randomUUID()), { mode: 0o600 }); }
const components = [{ key: 'cli.randomId', value: randomId }, { key: 'cli.timezone', value: Intl.DateTimeFormat().resolvedOptions().timeZone }, { key: 'cli.osVersion', value: release().slice(0, 32) }];
try { // macOS: the hardware UUID survives reinstalls; elsewhere only the random id is sent
  const uuid = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8' }).match(/"IOPlatformUUID" = "([0-9A-F-]{36})"/)?.[1];
  if (uuid) components.push({ key: 'cli.platformUuid', value: uuid });
} catch {}
const headers = { 'content-type': 'application/json', 'x-publishable-key': pk };
const { nonce } = await (await fetch(`${base}/v1/challenge?difficulty=${bits}`, { headers })).json();
const zeroBits = (d) => { let n = 0; for (const b of d) { if (b === 0) { n += 8; continue; } n += Math.clz32(b) - 24; break; } return n; };
let pow = 0; while (zeroBits(createHash('sha256').update(`${nonce}:${pow}`).digest()) < Number(bits)) pow++;
const canonical = `${nonce}|${components.map((c) => `${c.key}=${c.value}`).sort().join('|')}`; // sort the key=value strings
const sig = createHmac('sha256', seal).update(canonical).digest('hex');
const res = await fetch(`${base}/v1/identify`, { method: 'POST', headers, body: JSON.stringify({ platform: 'cli', nonce, sig, components, agentVersion: 'cli-node-1', pow: String(pow) }) });
console.log(JSON.stringify(await res.json(), null, 2)); // hand `attestation` to your backend for /v1/eligibility
