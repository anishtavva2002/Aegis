"""End-to-end: real proxy process, real pipes, fake MCP server behind it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aegis.gateway import verify_log

ROOT = Path(__file__).resolve().parents[2]
SERVER = Path(__file__).with_name("fake_mcp_server.py")


def rpc(msg_id: int, method: str, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}


def run_proxy(
    policy_path: Path, audit_path: Path, tmp_path: Path, lines: list[str], *extra: str
) -> tuple[list[Any], list[str]]:
    server_log = tmp_path / "server_calls.log"
    env = {**os.environ, "PYTHONPATH": str(ROOT), "FAKE_MCP_LOG": str(server_log)}
    cmd = [
        sys.executable, "-m", "aegis.cli", "mcp-proxy",
        "--gateway-policy", str(policy_path), "--gateway-audit", str(audit_path),
        "--agent-id", "agent", *extra, "--", sys.executable, str(SERVER),
    ]
    proc = subprocess.run(
        cmd, input="\n".join(lines) + "\n", capture_output=True, text=True,
        env=env, cwd=ROOT, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    replies = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    reached = server_log.read_text().split() if server_log.exists() else []
    return replies, reached


def by_id(replies: list[Any]) -> dict[Any, Any]:
    return {r["id"]: r for r in replies if isinstance(r, dict)}


def test_end_to_end_blocking_filtering_and_redaction(
    policy_path: Path, audit_path: Path, tmp_path: Path
) -> None:
    lines = [
        json.dumps(rpc(1, "initialize")),
        json.dumps(rpc(2, "tools/list")),
        json.dumps(rpc(3, "tools/call", name="read_file", arguments={"path": "/workspace/ok.txt"})),
        json.dumps(rpc(4, "tools/call", name="read_file", arguments={"path": "/etc/shadow"})),
        json.dumps(rpc(5, "tools/call", name="wipe_disk", arguments={})),
        json.dumps(rpc(6, "tools/call", name="run_shell", arguments={"command": "ls"})),
        json.dumps(rpc(7, "tools/call", name="read_file", arguments={"path": "/workspace/leak.txt"})),
    ]
    replies, reached = run_proxy(policy_path, audit_path, tmp_path, lines)
    got = by_id(replies)

    assert got[1]["result"]["serverInfo"]["name"] == "fake"
    assert [t["name"] for t in got[2]["result"]["tools"]] == ["read_file", "run_shell"]
    assert "ok:read_file:/workspace/ok.txt" in got[3]["result"]["content"][0]["text"]
    for blocked in (4, 5, 6):
        assert got[blocked]["error"]["code"] == -32001, blocked
    leaked = got[7]["result"]["content"][0]["text"]
    assert "AKIA" not in leaked and "hunter2" not in leaked

    # Blocked calls must never have reached the real server.
    assert reached == ["read_file", "read_file"]
    ok, count, error = verify_log(audit_path)
    assert ok, error
    assert count >= 6


def test_batch_and_garbage_input(policy_path: Path, audit_path: Path, tmp_path: Path) -> None:
    batch = [
        rpc(10, "tools/call", name="read_file", arguments={"path": "/workspace/a"}),
        rpc(11, "tools/call", name="wipe_disk", arguments={}),
    ]
    replies, reached = run_proxy(
        policy_path, audit_path, tmp_path, ["this is not json", json.dumps(batch)]
    )
    flat: list[Any] = []
    for r in replies:
        flat.extend(r if isinstance(r, list) else [r])
    got = by_id(flat)
    assert any(r.get("error", {}).get("code") == -32700 for r in flat)
    assert "result" in got[10] and got[11]["error"]["code"] == -32001
    assert reached == ["read_file"]


def test_block_injection_flag(policy_path: Path, audit_path: Path, tmp_path: Path) -> None:
    lines = [
        json.dumps(rpc(1, "tools/call", name="read_file", arguments={"path": "/workspace/inject.txt"}))
    ]
    allowed, _ = run_proxy(policy_path, audit_path, tmp_path, lines)
    assert "result" in allowed[0]
    blocked, _ = run_proxy(policy_path, audit_path, tmp_path, lines, "--block-injection")
    assert blocked[0]["error"]["code"] == -32001


def test_unknown_agent_refused(policy_path: Path, audit_path: Path, tmp_path: Path) -> None:
    cmd = [
        sys.executable, "-m", "aegis.cli", "mcp-proxy",
        "--gateway-policy", str(policy_path), "--gateway-audit", str(audit_path),
        "--agent-id", "ghost", "--", sys.executable, str(SERVER),
    ]
    proc = subprocess.run(
        cmd, input="", capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)}, timeout=60, check=False,
    )
    assert proc.returncode == 2 and "not in the policy" in proc.stderr


@pytest.mark.parametrize("flag", ["--no-redact"])
def test_no_redact_flag(policy_path: Path, audit_path: Path, tmp_path: Path, flag: str) -> None:
    lines = [
        json.dumps(rpc(1, "tools/call", name="read_file", arguments={"path": "/workspace/leak.txt"}))
    ]
    replies, _ = run_proxy(policy_path, audit_path, tmp_path, lines, flag)
    assert "AKIA" in replies[0]["result"]["content"][0]["text"]
