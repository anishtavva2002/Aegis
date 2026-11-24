"""Human-in-the-loop approvals for calls the policy marks `ask`."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from aegis.gateway.models import ToolCall

PENDING, APPROVED, DENIED, EXPIRED = "pending", "approved", "denied", "expired"


@dataclass
class Approval:
    id: str
    call: ToolCall
    created: float
    status: str = PENDING
    resolved_by: str | None = None

    def summary(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "agent_id": self.call.agent_id,
            "tool": self.call.tool,
            "args": self.call.args,
            "resolved_by": self.resolved_by,
        }


class ApprovalStore:
    """In-memory queue with expiry. Single process only; use a shared store to scale out."""

    def __init__(
        self,
        ttl: float = 300.0,
        max_pending: int = 1000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl
        self._max_pending = max_pending
        self._clock = clock
        self._items: dict[str, Approval] = {}
        self._lock = threading.Lock()

    def _expire(self) -> None:
        now = self._clock()
        for item in self._items.values():
            if item.status == PENDING and now - item.created > self._ttl:
                item.status = EXPIRED

    def create(self, call: ToolCall) -> Approval | None:
        """Queue a call; returns None when the pending queue is full (caller must deny)."""
        with self._lock:
            self._expire()
            if sum(1 for i in self._items.values() if i.status == PENDING) >= self._max_pending:
                return None
            item = Approval(id=secrets.token_urlsafe(12), call=call, created=self._clock())
            self._items[item.id] = item
            return item

    def get(self, approval_id: str) -> Approval | None:
        with self._lock:
            self._expire()
            return self._items.get(approval_id)

    def pending(self) -> list[Approval]:
        with self._lock:
            self._expire()
            return [i for i in self._items.values() if i.status == PENDING]

    def resolve(self, approval_id: str, approve: bool, by: str) -> Approval | None:
        """Resolve a pending approval exactly once. Returns None if unknown or not pending."""
        with self._lock:
            self._expire()
            item = self._items.get(approval_id)
            if item is None or item.status != PENDING:
                return None
            item.status = APPROVED if approve else DENIED
            item.resolved_by = by
            return item
