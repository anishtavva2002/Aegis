# Security policy

AEGIS v1 is a developer sandbox prototype, not a hardened hostile-code execution service.
Never expose the Docker daemon or Docker socket to untrusted users. Use a dedicated disposable
host or VM for untrusted workloads. Keep network disabled, preserve read-only rootfs and
resource limits, and review changes to policy thresholds. Report vulnerabilities privately.

## Gateway and MCP proxy (v1.2)

The gateway is a guardrail for AI agents that may be manipulated or mistaken. It is not a defence
against a malicious operator, a compromised host, or an agent that can reach its tools without
going through Aegis. Risk scoring is heuristic and can be evaded by obfuscation, so prefer narrow
path and host allowlists. The audit log is tamper-evident, not tamper-proof: anyone who can
rewrite the whole file can re-chain it, so copy the newest hash to an external append-only store.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full list of threats, mitigations and
residual risks. Run a single gateway replica until rate limits and approvals use a shared store.
Report vulnerabilities privately to the maintainer.
