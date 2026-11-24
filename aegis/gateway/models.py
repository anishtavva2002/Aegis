from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # requires human approval


class ToolCall(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex, max_length=64)


class Decision(BaseModel):
    effect: Effect
    reason: str
    rule: str = "default"
    risk: int = 0
    request_id: str = ""
    approval_id: str | None = None
