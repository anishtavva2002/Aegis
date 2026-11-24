# Threat model

Scope: the Aegis **gateway** and **MCP proxy** (v1.2). The Docker sandbox has its own caveats in
the README and `SECURITY.md`.

## What Aegis protects against

An AI agent that has been **manipulated** (prompt injection in a web page, file or tool result) or
is simply **mistaken**, and tries to use its tools in ways the operator did not intend: reading
files outside its workspace, calling arbitrary hosts, running destructive commands, leaking
credentials, or hammering a tool.

## What Aegis does not protect against

- A **malicious operator** or anyone who can edit the policy file, the audit log directory or the
  process memory. Aegis is a guardrail for agents, not a defence against the host's owner.
- **A compromised host or container escape.** The gateway trusts the machine it runs on.
- **Agents that bypass it.** In `/v1/decide` mode the agent runtime must honour the decision. The
  MCP proxy is stronger because it sits in the data path, but only for MCP traffic that goes
  through it. Anything the agent can reach directly (a shell, a network socket) is out of scope.
- **Semantic attacks that look legitimate**, e.g. an allowed `read_file` of a sensitive file inside
  the allowed directory, or exfiltration through an allowed host.

## Assets and trust boundaries

| Asset | Where it lives | Boundary |
|---|---|---|
| Policy (what each agent may do) | YAML file, read at start and on reload | Operator -> gateway |
| Agent API keys | Agents hold the key; the policy holds only its SHA-256 | Agent -> gateway |
| Admin token | `AEGIS_ADMIN_TOKEN` environment variable | Operator -> gateway |
| Audit log | Append-only JSONL, hash-chained | Gateway -> disk |
| Tool arguments and results | In flight through the gateway / proxy | Agent <-> tool server |

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | Agent calls a tool it should not have | Deny by default: unknown agent, unlisted tool and undeclared arguments are blocked | Policy mistakes: an over-broad rule is still allowed |
| 2 | Path traversal (`/workspace/../etc/passwd`) | Paths are normalised before the prefix check; sibling directories (`/workspace-evil`) do not match | Symlinks inside the allowed directory are not resolved by the gateway |
| 3 | Exfiltration to an attacker host, including `https://good.com@evil.com` | URL host allowlist that parses the real host | Allowed hosts can still be abused (e.g. a public paste API) |
| 4 | Dangerous commands, SSRF to cloud metadata, leaked keys in arguments | Heuristic risk score: deny at or above 80, ask at or above 50 | **Heuristic.** Obfuscation (`r""m -rf`, base64, split strings) can evade it. Do not rely on it alone; allowlist the tool's arguments instead |
| 5 | Prompt injection in tool output | Optional output blocking (`--block-injection`); secrets are redacted | Pattern-based; novel phrasings are missed |
| 6 | Secrets returned by a tool reach the model | Output redaction (AWS keys, GitHub tokens, bearer tokens, private keys, `password=`-style values) | Only known shapes are caught |
| 7 | Request flooding | Per-agent token bucket; arguments over 256 KB are rejected | In-memory per process; a multi-replica deployment multiplies the limit |
| 8 | Forged or stolen agent key | Constant-time comparison of key hashes; failures are audited and counted | No key expiry or rotation tooling yet |
| 9 | Unauthorised approval of a risky call | Admin-token-protected endpoint; approvals are single-use, expire after 5 minutes, are audited with the approver name, and a failed audit write leaves the approval pending | One shared admin token, no per-approver identity |
| 10 | Tampering with the audit log | Each record hashes its predecessor with a sequence number; `aegis verify-log` detects edits, deletions and reordering; the gateway refuses to append to a tampered log | **Whoever can rewrite the whole file can re-chain it.** Ship the latest hash to an external, append-only store to close this gap |
| 11 | Gateway failure leading to an open door | Fail closed: any evaluation error, or an audit write that fails, results in `deny` | Availability: if the gateway is down, protected agents stop |
| 12 | Bad policy pushed by reload | Reload validates first; an invalid policy keeps the previous one | A valid but wrong policy is applied |
| 13 | Secrets in the audit log | Only a hash of the arguments is stored | Tool names, agent ids and denial reasons are stored in clear |
| 14 | Malformed MCP traffic used to smuggle a call | Non-JSON, non-object and malformed `tools/call` messages are rejected, not forwarded; non-JSON from the server is dropped | Only stdio transport is covered today |

## Operating guidance

1. Keep the policy file and audit directory writable only by the gateway user.
2. Run one gateway replica until rate limits and approvals move to a shared store.
3. Set `AEGIS_ADMIN_TOKEN` from a secret store; never put it in the policy or image.
4. Periodically copy the newest audit hash somewhere the gateway cannot write.
5. Prefer narrow allowlists (paths, hosts) over relying on risk scoring.
