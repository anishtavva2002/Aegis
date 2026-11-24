"""Measure Aegis decision latency. Usage: python scripts/bench.py [N]"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

import yaml

from aegis.gateway import Aegis, AuditLog, Policy, ToolCall

POLICY = {
    "version": 1,
    "agents": {
        "bot": {
            "key_sha256": "0" * 64,
            "rate_limit": {"per_minute": 10_000_000},
            "tools": {
                "read_file": {
                    "constraints": {
                        "path": {"required": True, "prefix": ["/workspace"], "max_len": 256,
                                 "deny_regex": [r"\.env$"]}
                    }
                }
            },
        }
    },
}


def bench(n: int, fsync: bool, workdir: Path) -> dict[str, float]:
    policy_path = workdir / f"policy-{fsync}.yaml"
    policy_path.write_text(yaml.safe_dump(POLICY))
    engine = Aegis(
        Policy.load(policy_path), AuditLog(workdir / f"audit-{fsync}.jsonl", fsync=fsync)
    )
    call = ToolCall(agent_id="bot", tool="read_file", args={"path": "/workspace/src/main.py"})
    for _ in range(200):  # warm up
        engine.decide(call)
    samples = []
    start = time.perf_counter()
    for _ in range(n):
        t0 = time.perf_counter()
        engine.decide(call)
        samples.append(time.perf_counter() - t0)
    total = time.perf_counter() - start
    samples.sort()
    return {
        "n": n,
        "p50_ms": statistics.median(samples) * 1000,
        "p99_ms": samples[int(0.99 * (n - 1))] * 1000,
        "max_ms": samples[-1] * 1000,
        "per_sec": n / total,
    }


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    with tempfile.TemporaryDirectory() as tmp:
        for fsync, count in ((False, n), (True, min(n, 500))):
            r = bench(count, fsync, Path(tmp))
            label = "fsync per record (durable)" if fsync else "no fsync (OS-buffered)"
            print(
                f"{label:28} n={r['n']:<6} p50={r['p50_ms']:.3f}ms p99={r['p99_ms']:.3f}ms "
                f"max={r['max_ms']:.2f}ms  {r['per_sec']:.0f} decisions/s"
            )


if __name__ == "__main__":
    main()
