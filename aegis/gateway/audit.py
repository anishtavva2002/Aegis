"""Tamper-evident audit log: append-only JSONL where each record hashes its predecessor."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from aegis.gateway.models import Decision, ToolCall

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(record)).hexdigest()


def args_digest(args: dict[str, Any]) -> str:
    """Hash of arguments, so the log proves what was requested without storing secrets."""
    return hashlib.sha256(_canonical(args)).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, fsync: bool = True) -> None:
        self.path = Path(path)
        self._fsync = fsync
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        ok, count, error = verify_log(self.path)
        if not ok:
            raise RuntimeError(f"audit log failed verification, refusing to append: {error}")
        last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
        return count, json.loads(last)["hash"]

    def append(self, call: ToolCall, decision: Decision) -> str:
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq + 1,
                "ts": time.time(),
                "prev": self._prev,
                "request_id": decision.request_id or call.request_id,
                "agent": call.agent_id,
                "tool": call.tool,
                "args_sha256": args_digest(call.args),
                "effect": decision.effect.value,
                "rule": decision.rule,
                "reason": decision.reason,
                "risk": decision.risk,
            }
            record["hash"] = _digest(self._prev, record)
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
                if self._fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)
            self._seq, self._prev = record["seq"], record["hash"]
            return str(record["hash"])


def verify_log(path: str | Path) -> tuple[bool, int, str | None]:
    """Return (ok, record_count, error). Detects edits, deletions, reordering, truncation gaps."""
    prev, expected_seq = GENESIS, 1
    p = Path(path)
    if not p.exists():
        return True, 0, None
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            record = json.loads(line)
            claimed = record.pop("hash")
        except (ValueError, KeyError):
            return False, expected_seq - 1, f"line {lineno}: malformed record"
        if record.get("seq") != expected_seq:
            return False, expected_seq - 1, f"line {lineno}: sequence gap"
        if record.get("prev") != prev or _digest(prev, record) != claimed:
            return False, expected_seq - 1, f"line {lineno}: hash chain broken"
        prev, expected_seq = claimed, expected_seq + 1
    return True, expected_seq - 1, None
