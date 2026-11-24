from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from aegis.gateway import Aegis, AuditLog, Policy

KEY = "test-key-123"
KEY_HASH = hashlib.sha256(KEY.encode()).hexdigest()

POLICY = {
    "version": 1,
    "risk": {"ask_threshold": 50, "deny_threshold": 80},
    "agents": {
        "bot": {
            "key_sha256": KEY_HASH,
            "rate_limit": {"per_minute": 5},
            "tools": {
                "read_file": {
                    "constraints": {
                        "path": {
                            "required": True,
                            "prefix": ["/workspace"],
                            "deny_regex": [r"\.env$"],
                            "max_len": 256,
                        }
                    }
                },
                "http_get": {
                    "constraints": {"url": {"required": True, "host_allow": ["api.github.com"]}}
                },
                "run_shell": {
                    "effect": "ask",
                    "constraints": {"command": {"required": True, "max_len": 200}},
                },
                "note": {"allow_extra_args": True},
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
    return Aegis(Policy.load(policy_path), AuditLog(audit_path))
