import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync, appendFileSync, readdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const script = join(here, 'sync-apple-sources.mjs');
const TARGETS = ['flutter/ios/Classes/FingerPrintChecker', 'react-native/ios/FingerPrintChecker'];

function tempRoot() {
  const root = mkdtempSync(join(tmpdir(), 'fpc-sync-'));
  mkdirSync(join(root, 'apple/Sources'), { recursive: true });
  cpSync(join(repo, 'apple/Sources/FingerPrintChecker'), join(root, 'apple/Sources/FingerPrintChecker'), { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: root });
  spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'x'], { cwd: root });
  return root;
}
const run = (root, ...args) => spawnSync('node', [script, '--root', root, ...args], { encoding: 'utf8' });

test('sync then check passes, writes SOURCE and privacy manifest', () => {
  const root = tempRoot();
  try {
    assert.equal(run(root).status, 0);
    for (const t of TARGETS) {
      assert.ok(existsSync(join(root, t, 'Resources/PrivacyInfo.xcprivacy')));
      const src = readFileSync(join(root, t, 'SOURCE'), 'utf8');
      assert.match(src, /[0-9a-f]{40}/);
      assert.match(src, /do not edit/);
    }
    assert.equal(run(root, '--check').status, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('check fails when one byte of a vendored file is changed', () => {
  const root = tempRoot();
  try {
    run(root);
    const f = join(root, TARGETS[0], 'Version.swift');
    appendFileSync(f, '\n');
    const r = run(root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stdout + r.stderr, /Version\.swift/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('check fails on extra and missing files', () => {
  const root = tempRoot();
  try {
    run(root);
    writeFileSync(join(root, TARGETS[1], 'Extra.swift'), 'x');
    let r = run(root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stdout + r.stderr, /Extra\.swift/);
    rmSync(join(root, TARGETS[1], 'Extra.swift'));
    rmSync(join(root, TARGETS[0], 'Crypto.swift'));
    r = run(root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stdout + r.stderr, /Crypto\.swift/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('check ignores the SOURCE file', () => {
  const root = tempRoot();
  try {
    run(root);
    writeFileSync(join(root, TARGETS[0], 'SOURCE'), 'changed');
    assert.equal(run(root, '--check').status, 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
