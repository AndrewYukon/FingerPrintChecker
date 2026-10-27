# @fingerprintchecker/cli

Command line and local [MCP](https://modelcontextprotocol.io) server for [FingerPrint Checker](https://fpchecker.com). Manage projects, environments, events, rulesets and webhooks from a terminal, or let an AI assistant (Claude Desktop, Cursor, Claude Code) read them for you. Node 18+.

```sh
export FPCHECKER_MANAGEMENT_KEY=mk_…          # created in the console at https://fpchecker.com/console/api-keys ("API keys"; owners and admins)
npx -y @fingerprintchecker/cli projects list
```

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `FPCHECKER_MANAGEMENT_KEY` | yes | A management key (`mk_…`). Read-scope keys can only read. |
| `FPCHECKER_API_URL` | no | API origin. Default `https://api.fpchecker.com`. Must be https, except `localhost`, `127.0.0.1` and `::1`; anything else exits 2. |

The key is read **only** from the environment. A command-line argument that starts with `mk_` (or `--opt=mk_…`) is refused with exit code 2, because arguments end up in shell history and process listings. The key is never printed, in output, errors or `--json`.

Exit codes: `0` ok, `1` the server refused the request or could not be reached, `2` usage error (bad arguments, no key, key on the command line).

## Commands

Add `--json` to any command to print the server's JSON instead of a table.

```
fpchecker projects list
fpchecker projects get <projectId>
fpchecker projects create --name <name>
fpchecker environments create <projectId> --name <env>
fpchecker keys rotate <projectId> --key secret|publishable
fpchecker events list <projectId> [--visitor-id <id>] [--limit <n>] [--since <time>] [--cursor <c>]
fpchecker events get <projectId> <eventId>
fpchecker visitors get <projectId> <visitorId>
fpchecker ruleset get <projectId>
fpchecker ruleset set <projectId> --file <ruleset.json>
fpchecker ruleset test <projectId> --event <eventId> [--file <ruleset.json>]
fpchecker webhooks list <projectId>
fpchecker usage
fpchecker audit [--limit <n>] [--cursor <c>]
fpchecker mcp [--allow-writes]
```

`ruleset set` takes the whole ruleset, including `ifVersion` (the version it is based on); a stale version is refused. `ruleset test` is a dry run against a stored event; without `--file` it tests the saved ruleset.

## MCP server

`fpchecker mcp` speaks MCP over stdio. It is **read-only by default**. The write tools `update_ruleset`, `create_environment` and `rotate_key` exist only when you start it with `--allow-writes`, and a read-scope key cannot use them anyway.

Read tools: `list_projects`, `get_project`, `get_usage`, `search_events`, `get_event`, `get_visitor`, `get_ruleset`, `test_ruleset`, `list_webhooks`, `list_audit`. Results are the server's JSON, unsummarized. Ids are validated before any request is made.

### Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fpchecker": {
      "command": "npx",
      "args": ["-y", "@fingerprintchecker/cli", "mcp"],
      "env": { "FPCHECKER_MANAGEMENT_KEY": "mk_…" }
    }
  }
}
```

### Cursor

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "fpchecker": {
      "command": "npx",
      "args": ["-y", "@fingerprintchecker/cli", "mcp"],
      "env": { "FPCHECKER_MANAGEMENT_KEY": "mk_…" }
    }
  }
}
```

### Claude Code

```sh
claude mcp add --env FPCHECKER_MANAGEMENT_KEY=mk_… fpchecker -- npx -y @fingerprintchecker/cli mcp
```

To allow writes, append `--allow-writes` after `mcp`.

## License

Apache-2.0
