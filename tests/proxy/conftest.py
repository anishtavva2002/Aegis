from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegis.gateway import Aegis, AuditLog, Policy

POLICY = {
    "version": 1,
    "agents": {
        "agent": {
            "key_sha256": "0" * 64,
            "rate_limit": {"per_minute": 1000},
            "tools": {
                "read_file": {
                    "constraints": {
                        "path": {"required": True, "prefix": ["/workspace"], "max_len": 256}
                    }
                },
                "run_shell": {
                    "effect": "ask",
                    "constraints": {"command": {"required": True, "max_len": 200}},
                },
            },
        }
    },
}


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(POLICY))
    return path


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def engine(policy_path: Path, audit_path: Path) -> Aegis:
    return Aegis(Policy.load(policy_path), AuditLog(audit_path, fsync=False))
