#!/usr/bin/env node
import { run } from './commands/index.js';

const code = await run(process.argv.slice(2), {
  env: process.env,
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
});
process.exitCode = code;
