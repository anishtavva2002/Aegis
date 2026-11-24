# Security policy

AEGIS v1 is a developer sandbox prototype, not a hardened hostile-code execution service.
Never expose the Docker daemon or Docker socket to untrusted users. Use a dedicated disposable
host or VM for untrusted workloads. Keep network disabled, preserve read-only rootfs and
resource limits, and review changes to policy thresholds. Report vulnerabilities privately.
