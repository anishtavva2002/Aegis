import json
from pathlib import Path
from .models import Decision

DEFAULT_POLICY = {
    "deny_threshold": 80,
    "approval_threshold": 35,
    "max_timeout_seconds": 20,
    "memory_limit": "128m",
    "nano_cpus": 500000000,
    "pids_limit": 64,
    "network_disabled": True,
    "read_only_rootfs": True,
    "runtime": None
}

class PolicyEngine:
    def __init__(self, policy_path=None):
        self.policy = DEFAULT_POLICY.copy()
        if policy_path:
            loaded = json.loads(Path(policy_path).read_text(encoding="utf-8"))
            self.policy.update(loaded)
        self._validate()

    def _validate(self):
        if not (1 <= int(self.policy["max_timeout_seconds"]) <= 120):
            raise ValueError("max_timeout_seconds must be between 1 and 120.")
        if not (1 <= int(self.policy["pids_limit"]) <= 256):
            raise ValueError("pids_limit must be between 1 and 256.")
        if not (1 <= int(self.policy["nano_cpus"]) <= 2_000_000_000):
            raise ValueError("nano_cpus must be between 1 and 2 CPUs.")
        if not self.policy["network_disabled"]:
            raise ValueError("Network must remain disabled in this v1 implementation.")
        if self.policy.get("runtime") not in (None, "runsc", "kata-runtime", "kata"):
            raise ValueError("runtime must be one of: null, runsc, kata-runtime, kata.")
        if not self.policy["read_only_rootfs"]:
            raise ValueError("Read-only root filesystem must remain enabled in v1.")

    def decide(self, risk_score: int, static_decision: Decision):
        if risk_score >= int(self.policy["deny_threshold"]) or static_decision == Decision.DENY:
            return Decision.DENY
        if risk_score >= int(self.policy["approval_threshold"]) or static_decision == Decision.APPROVAL_REQUIRED:
            return Decision.APPROVAL_REQUIRED
        return Decision.ALLOW
