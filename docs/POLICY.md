# Policy reference (gateway)

Policies are YAML, validated at load time. Unknown fields are rejected, so typos fail loudly.
Check one with `aegis check-policy policy.yaml`.

```yaml
version: 1

risk:
  ask_threshold: 50    # risk score >= this needs approval
  deny_threshold: 80   # risk score >= this is blocked

agents:
  research-agent:               # the agent_id sent in requests
    key_sha256: "<64 hex>"      # from `aegis hash-key`; the key itself is never stored
    rate_limit:
      per_minute: 60            # token bucket, per agent
    tools:                      # anything not listed is denied
      read_file:
        effect: allow           # allow (default) | ask (always needs a human)
        allow_extra_args: false # undeclared arguments are denied unless true
        constraints:
          path:
            required: true
            prefix: ["/workspace"]
            deny_regex: ['\.env$']
            max_len: 512
```

## Decision order

1. Unknown agent: deny (`unknown_agent`)
2. Tool not listed: deny (`tool_not_allowed`)
3. Each argument: undeclared (`undeclared_arg`) or breaks a constraint (`arg_constraint`): deny
4. Missing required argument: deny (`arg_required`)
5. Risk score at or above `deny_threshold`: deny (`risk_deny`)
6. Rate limit exceeded: deny (`rate_limit`)
7. Tool `effect: ask`, or risk at or above `ask_threshold`: **ask**
8. Otherwise: allow

Every decision, including denials and authentication failures, is written to the audit log. If
evaluation throws, the answer is deny (`fail_closed`); if the audit write fails, deny
(`audit_down`).

## Argument constraints

| Field | Applies to | Meaning |
|---|---|---|
| `required` | any | Argument must be present |
| `enum` | any | Value must equal one of the listed values |
| `max_len` | string | Maximum length |
| `prefix` | string path | Normalised path must be inside one of the prefixes |
| `allow_regex` | string | Must match at least one pattern |
| `deny_regex` | string | Must match none |
| `host_allow` | string URL | `http(s)` URL whose real host is in the list |
| `analyze_python` | string | Run the value through the sandbox static analyzer and fold its risk score in |

String constraints reject non-strings and values containing NUL bytes.

## Approvals

When a call returns `ask`, the response carries an `approval_id`.

- Agent polls `GET /v1/approvals/{id}` with its own key and an `X-Aegis-Agent` header.
- A human lists `GET /v1/admin/approvals` and resolves with
  `POST /v1/admin/approvals/{id}/approve` or `/deny` (admin token, optional `X-Aegis-Approver`).
- Approvals are single-use and expire after 5 minutes.

## Operations

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/decide` | agent key | Decide a proposed call |
| `POST /v1/admin/reload` | admin token | Re-read the policy; an invalid file keeps the old one |
| `GET /metrics` | admin token (or `AEGIS_METRICS_PUBLIC=1`) | Prometheus metrics |
| `GET /healthz` | none | Liveness |

Environment: `AEGIS_ADMIN_TOKEN`, `AEGIS_METRICS_PUBLIC`, `AEGIS_AUDIT_FSYNC` (set `0` to skip
fsync per record: faster, but the last records can be lost on power failure).
