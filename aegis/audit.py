"""Sandbox audit log: append-only JSONL, hash-chained so edits and deletions are detectable."""

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, row: dict) -> str:
    body = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


class AuditLogger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path.exists() and self.path.stat().st_size:
            ok, _, error = verify_chain(self.path)
            if not ok:
                raise RuntimeError(f"audit log failed verification, refusing to append: {error}")
            last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
            self._prev = json.loads(last)["hash"]

    def record(self, event: dict):
        with self._lock:
            row = {"timestamp": datetime.now(timezone.utc).isoformat(), **event,
                   "prev": self._prev}
            row["hash"] = _digest(self._prev, row)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
            self._prev = row["hash"]
            return row


def verify_chain(path) -> tuple[bool, int, str | None]:
    """Return (ok, record_count, error). Missing or empty logs are valid."""
    p = Path(path)
    prev, count = GENESIS, 0
    if not p.exists():
        return True, 0, None
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            row = json.loads(line)
            claimed = row.pop("hash")
        except (ValueError, KeyError):
            return False, count, f"line {lineno}: malformed record"
        if row.get("prev") != prev or _digest(prev, row) != claimed:
            return False, count, f"line {lineno}: hash chain broken"
        prev, count = claimed, count + 1
    return True, count, None
