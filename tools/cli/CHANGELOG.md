# Changelog

## 0.1.0

- First release: the `fpchecker` command and a local stdio MCP server over the Management API.
- Commands for projects, environments, key rotation, events, visitors, rulesets, webhooks, usage and the audit log; `--json` on all of them.
- The management key is read only from `FPCHECKER_MANAGEMENT_KEY`; a key on the command line is refused.
- MCP tools are read-only unless started with `--allow-writes`.
