"""Heuristic risk scoring over tool-call arguments (0-100)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

_PATTERNS: list[tuple[str, int, str]] = [
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b", 90, "destructive rm"),
    (r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b", 90, "pipe-to-shell"),
    (r"\b(nc|ncat|netcat)\b[^\n]*\s-e\b", 90, "reverse shell"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 90, "private key material"),
    (r"169\.254\.169\.254|metadata\.google\.internal", 85, "cloud metadata endpoint"),
    (r"\bAKIA[0-9A-Z]{16}\b", 80, "AWS access key"),
    (r"/etc/(passwd|shadow)\b", 70, "system credential file"),
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions", 60, "prompt injection"),
    (r"(?i)\b(api[_-]?key|secret|password|token)\b\s*[=:]\s*\S{8,}", 60, "inline credential"),
    (r"(?i)base64\s+(-d|--decode)", 30, "base64 decode"),
]
_COMPILED = [(re.compile(p), score, label) for p, score, label in _PATTERNS]


def _strings(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, depth + 1)


def score(args: dict[str, Any]) -> tuple[int, list[str]]:
    """Return (risk 0-100, labels of matched signals). Highest hit dominates; extras add 5 each."""
    hits: list[tuple[int, str]] = []
    for text in _strings(args):
        for pattern, points, label in _COMPILED:
            if pattern.search(text):
                hits.append((points, label))
    if not hits:
        return 0, []
    hits.sort(reverse=True)
    total = min(100, hits[0][0] + 5 * (len(hits) - 1))
    return total, sorted({label for _, label in hits})
