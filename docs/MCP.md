# Guarding an MCP server

`aegis mcp-proxy` wraps any stdio MCP server. The agent talks to Aegis; Aegis talks to the real
server.

```
agent  <-- stdio -->  aegis mcp-proxy  <-- stdio -->  real MCP server
```

## What it does

- **`tools/call`** is decided by the policy. Blocked calls get a JSON-RPC error (code `-32001`)
  and **never reach the server**. Calls that need approval are refused unless you pass
  `--approve-prompt`, which asks on the terminal.
- **`tools/list`** results are filtered to the tools the agent's policy allows, so the model
  never sees tools it cannot use.
- **Tool output** is scanned: secrets are redacted (`--no-redact` turns that off) and, with
  `--block-injection`, output that looks like prompt injection is replaced by an error.
- **Malformed input** is rejected, not forwarded.
- Everything is written to the hash-chained audit log.

## Setup

1. Write a policy for the agent (see `policies/gateway.example.yaml` and `docs/POLICY.md`). The
   proxy runs in-process, so `key_sha256` is required by the schema but not checked.
2. Run it in front of your server:

```bash
aegis mcp-proxy \
  --gateway-policy policy.yaml --gateway-audit audit.jsonl \
  --agent-id research-agent \
  -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

3. Point your MCP client at the proxy instead of the server. For a client that uses an
   `mcpServers` config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "aegis",
      "args": [
        "mcp-proxy",
        "--gateway-policy", "/etc/aegis/policy.yaml",
        "--gateway-audit", "/var/log/aegis/audit.jsonl",
        "--agent-id", "research-agent",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

4. Verify the log any time: `aegis verify-log /var/log/aegis/audit.jsonl`.

## Limits

- stdio transport only. HTTP/SSE servers are not covered yet.
- The `--approve-prompt` flow needs a terminal (`/dev/tty`, or `CON` on Windows). With none
  available it refuses, which is the safe default.
- Argument constraints are only as good as the policy you write. Allowlist paths and hosts.
