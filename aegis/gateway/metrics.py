"""Dependency-free Prometheus text-format metrics."""

from __future__ import annotations

import threading

BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._decisions: dict[tuple[str, str], int] = {}
        self._events: dict[tuple[str, str], int] = {}
        self._bucket_counts = [0] * len(BUCKETS)
        self._sum = 0.0
        self._count = 0

    def observe_decision(self, effect: str, rule: str, seconds: float) -> None:
        with self._lock:
            key = (effect, rule)
            self._decisions[key] = self._decisions.get(key, 0) + 1
            self._count += 1
            self._sum += seconds
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    self._bucket_counts[i] += 1

    def event(self, name: str, kind: str = "") -> None:
        with self._lock:
            key = (name, kind)
            self._events[key] = self._events.get(key, 0) + 1

    def render(self) -> str:
        with self._lock:
            lines = ["# TYPE aegis_decisions_total counter"]
            for (effect, rule), n in sorted(self._decisions.items()):
                lines.append(
                    f'aegis_decisions_total{{effect="{_esc(effect)}",rule="{_esc(rule)}"}} {n}'
                )
            lines.append("# TYPE aegis_events_total counter")
            for (name, kind), n in sorted(self._events.items()):
                lines.append(f'aegis_events_total{{name="{_esc(name)}",kind="{_esc(kind)}"}} {n}')
            lines.append("# TYPE aegis_decision_seconds histogram")
            for bound, n in zip(BUCKETS, self._bucket_counts, strict=True):
                lines.append(f'aegis_decision_seconds_bucket{{le="{bound}"}} {n}')
            lines.append(f'aegis_decision_seconds_bucket{{le="+Inf"}} {self._count}')
            lines.append(f"aegis_decision_seconds_sum {self._sum:.9f}")
            lines.append(f"aegis_decision_seconds_count {self._count}")
            return "\n".join(lines) + "\n"
