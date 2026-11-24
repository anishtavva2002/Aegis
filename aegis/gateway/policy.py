"""Declarative policy: schema, loading, and per-argument constraint checks."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ArgConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: bool = False
    enum: list[Any] = Field(default_factory=list)
    max_len: int | None = None
    prefix: list[str] = Field(default_factory=list)  # path must live under one of these
    allow_regex: list[str] = Field(default_factory=list)  # must match at least one
    deny_regex: list[str] = Field(default_factory=list)  # must match none
    host_allow: list[str] = Field(default_factory=list)  # URL host allowlist
    analyze_python: bool = False  # run value through the sandbox's static analyzer

    @field_validator("allow_regex", "deny_regex")
    @classmethod
    def _compile(cls, v: list[str]) -> list[str]:
        for pattern in v:
            re.compile(pattern)  # fail at load time, not at request time
        return v

    def violation(self, value: Any) -> str | None:
        """Return a human-readable violation, or None if the value is acceptable."""
        if self.enum and value not in self.enum:
            return f"value not in allowed set {self.enum}"
        needs_str = self.max_len or self.prefix or self.allow_regex or self.deny_regex
        needs_str = needs_str or self.host_allow
        if not needs_str:
            return None
        if not isinstance(value, str):
            return "must be a string"
        if "\x00" in value:
            return "contains NUL byte"
        if self.max_len is not None and len(value) > self.max_len:
            return f"longer than {self.max_len} chars"
        if self.prefix and not _under_prefix(value, self.prefix):
            return f"path outside allowed prefixes {self.prefix}"
        for pattern in self.deny_regex:
            if re.search(pattern, value):
                return f"matches denied pattern {pattern!r}"
        if self.allow_regex and not any(re.search(p, value) for p in self.allow_regex):
            return "matches no allowed pattern"
        if self.host_allow:
            parsed = urlparse(value)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in ("http", "https") or host not in {
                h.lower() for h in self.host_allow
            }:
                return f"host {host or '?'!r} not in allowlist"
        return None


def _under_prefix(value: str, prefixes: list[str]) -> bool:
    normalized = posixpath.normpath(value)  # collapses '..' before comparing
    for prefix in prefixes:
        base = prefix.rstrip("/")
        if normalized == base or normalized.startswith(base + "/"):
            return True
    return False


class ToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    effect: Literal["allow", "ask"] = "allow"
    allow_extra_args: bool = False  # undeclared arguments are denied by default
    constraints: dict[str, ArgConstraint] = Field(default_factory=dict)


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    per_minute: int = Field(default=60, ge=1)


class AgentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    tools: dict[str, ToolRule] = Field(default_factory=dict)


class RiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ask_threshold: int = Field(default=50, ge=0, le=100)
    deny_threshold: int = Field(default=80, ge=0, le=100)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    risk: RiskConfig = Field(default_factory=RiskConfig)
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)
