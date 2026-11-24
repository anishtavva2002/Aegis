from __future__ import annotations

import threading
import time
from collections.abc import Callable


class TokenBucket:
    """Per-key token bucket. In-memory; swap for Redis when running multiple replicas."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, per_minute: int) -> bool:
        now = self._clock()
        rate = per_minute / 60.0
        with self._lock:
            tokens, last = self._state.get(key, (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1.0, now)
            return True
