// fpchecker CLI identify (Node 18+). Env: FPC_PK, FPC_INTENT (v2) or FPC_SEAL (v1), FPC_TENANT, FPC_BASE (default https://api.fpchecker.com), FPC_POW (default 16).
// v2 (recommended): node identify.mjs --intent <intentToken>   (your backend mints it with POST /v2/intents). v1: needs FPC_SEAL.
// Self-test: node identify.mjs --self-test   (checks ../../test-vectors/protocol-v2.json)
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, release } from 'node:os';

// --- protocol v2 canonical bytes: RFC 8785 (JCS) of a fixed object, written by hand (no JSON.stringify escaping) ---
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const jcsString = (s) => {
  if (typeof s !== 'string' || LONE_SURROGATE.test(s)) throw new Error('string is not well-formed UTF-16');
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    out += ch === '"' ? '\\"' : ch === '\\' ? '\\\\' : c === 8 ? '\\b' : c === 12 ? '\\f' : c === 10 ? '\\n' : c === 13 ? '\\r' : c === 9 ? '\\t'
      : c < 0x20 ? `\\u${c.toString(16).padStart(4, '0')}` : ch;
  }
  return `${out}"`;
};
const utf16Order = (a, b) => (a < b ? -1 : a > b ? 1 : 0); // JS string comparison is by UTF-16 code unit
export function identifyCanonical({ platform, agentVersion, challenge, components }) {
  if (typeof agentVersion !== 'string' || agentVersion.length > 64) throw new Error('bad agentVersion');
  const seen = new Set();
  for (const c of components) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(c.key)) throw new Error(`bad component key: ${c.key}`);
    if (seen.has(c.key)) throw new Error(`duplicate component key: ${c.key}`);
    seen.add(c.key);
  }
  const comps = [...components].sort((a, b) => utf16Order(a.key, b.key)).map((c) =>
    `{${c.hash === undefined ? '' : `"hash":${jcsString(c.hash)},`}"key":${jcsString(c.key)},"value":${jcsString(c.value)}}`);
  return `{"agentVersion":${jcsString(agentVersion)},"challenge":${jcsString(challenge)},"components":[${comps.join(',')}],"domain":"fpchecker.identify.v2","platform":${jcsString(platform)},"protocolVersion":2}`;
}
const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest();

function selfTest() {
  const v = JSON.parse(readFileSync(new URL('../../test-vectors/protocol-v2.json', import.meta.url), 'utf8'));
  let fail = 0;
  const check = (ok, msg) => { if (!ok) { fail++; console.error(`FAIL ${msg}`); } };
  for (const a of v.accept) {
    let canonical; try { canonical = identifyCanonical(a.input); } catch (e) { check(false, `${a.name}: ${e.message}`); continue; }
    check(canonical === a.canonical, `${a.name}: canonical`);
    check(sha256(canonical).toString('hex') === a.requestBindingHex, `${a.name}: requestBindingHex`);
    check(sha256(canonical).toString('base64') === a.clientDataHashBase64, `${a.name}: clientDataHashBase64`);
  }
  for (const r of v.reject) { let refused = false; try { identifyCanonical(r.input); } catch { refused = true; } check(refused, `${r.name}: must be refused`); }
  console.log(`${v.accept.length} accept + ${v.reject.length} reject cases, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

const args = process.argv.slice(2);
if (args.includes('--self-test')) selfTest();
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const { FPC_PK: pk, FPC_SEAL: seal, FPC_TENANT: tenant = 'fpchecker', FPC_BASE: base = 'https://api.fpchecker.com', FPC_POW: bits = '16' } = process.env;
const intent = flag('--intent') ?? process.env.FPC_INTENT;
if (!pk) { console.error('FPC_PK is not set'); process.exit(2); }
if (!intent && !seal) { console.error('give --intent <intentToken> (or FPC_INTENT) for v2, or FPC_SEAL for v1'); process.exit(2); }
const dir = `${homedir()}/.config/${tenant}`, idFile = `${dir}/device-id`;
let randomId; try { randomId = readFileSync(idFile, 'utf8').trim(); } catch { mkdirSync(dir, { recursive: true }); writeFileSync(idFile, (randomId = randomUUID()), { mode: 0o600 }); }
const components = [{ key: 'cli.randomId', value: randomId }, { key: 'cli.timezone', value: Intl.DateTimeFormat().resolvedOptions().timeZone }, { key: 'cli.osVersion', value: release().slice(0, 32) }];
try { // macOS: the hardware UUID survives reinstalls; elsewhere only the random id is sent
  const uuid = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8' }).match(/"IOPlatformUUID" = "([0-9A-F-]{36})"/)?.[1];
  if (uuid) components.push({ key: 'cli.platformUuid', value: uuid });
} catch {}
const headers = { 'content-type': 'application/json', 'x-publishable-key': pk };
const zeroBits = (d) => { let n = 0; for (const b of d) { if (b === 0) { n += 8; continue; } n += Math.clz32(b) - 24; break; } return n; };
const solve = (challenge) => { let pow = 0; while (zeroBits(createHash('sha256').update(`${challenge}:${pow}`).digest()) < Number(bits)) pow++; return String(pow); };

if (intent) { // v2: nothing is sealed or bound; the answer carries an opaque attestation
  const ch = await (await fetch(`${base}/v2/challenge?intent=${encodeURIComponent(intent)}&difficulty=${bits}`, { headers })).json();
  if (!ch.ok || typeof ch.challenge !== 'string') { console.error(JSON.stringify(ch)); process.exit(1); }
  const agentVersion = 'cli-node-0.2.0';
  identifyCanonical({ platform: 'cli', agentVersion, challenge: ch.challenge, components }); // refuse locally what the server refuses
  const res = await fetch(`${base}/v2/identify`, { method: 'POST', headers, body: JSON.stringify({ protocolVersion: 2, platform: 'cli', intentToken: intent, challenge: ch.challenge, agentVersion, components, pow: solve(ch.challenge) }) });
  const out = await res.json();
  console.log(JSON.stringify(out, null, 2)); // hand `attestation` to your backend for /v1/eligibility
  if (!res.ok || out.ok !== true || typeof out.attestation !== 'string' || out.attestation === '') process.exit(1); // a success without an attestation is a failure
} else {
  const { nonce } = await (await fetch(`${base}/v1/challenge?difficulty=${bits}`, { headers })).json();
  const canonical = `${nonce}|${components.map((c) => `${c.key}=${c.value}`).sort().join('|')}`; // sort the key=value strings
  const sig = createHmac('sha256', seal).update(canonical).digest('hex');
  const res = await fetch(`${base}/v1/identify`, { method: 'POST', headers, body: JSON.stringify({ platform: 'cli', nonce, sig, components, agentVersion: 'cli-node-1', pow: solve(nonce) }) });
  console.log(JSON.stringify(await res.json(), null, 2)); // hand `attestation` to your backend for /v1/eligibility
}
