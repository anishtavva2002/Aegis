from __future__ import annotations

from pathlib import Path

import pytest

from aegis.gateway import Aegis, AuditLog, Policy, ToolCall, verify_log


def _fill(engine: Aegis, n: int = 4) -> None:
    for i in range(n):
        engine.decide(ToolCall(agent_id="bot", tool="note", args={"text": str(i)}))


def test_chain_verifies(engine: Aegis, audit_path: Path) -> None:
    _fill(engine)
    assert verify_log(audit_path) == (True, 4, None)


def test_edit_detected(engine: Aegis, audit_path: Path) -> None:
    _fill(engine)
    audit_path.write_text(audit_path.read_text().replace('"allow"', '"deny"', 1))
    ok, _, err = verify_log(audit_path)
    assert not ok and err


def test_deleted_record_detected(engine: Aegis, audit_path: Path) -> None:
    _fill(engine)
    lines = audit_path.read_text().splitlines()
    del lines[1]
    audit_path.write_text("\n".join(lines) + "\n")
    assert not verify_log(audit_path)[0]


def test_reordered_detected(engine: Aegis, audit_path: Path) -> None:
    _fill(engine)
    lines = audit_path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    audit_path.write_text("\n".join(lines) + "\n")
    assert not verify_log(audit_path)[0]


def test_resume_continues_chain(engine: Aegis, audit_path: Path, policy_path: Path) -> None:
    _fill(engine, 2)
    restarted = Aegis(Policy.load(policy_path), AuditLog(audit_path))  # simulates a restart
    _fill(restarted, 2)
    assert verify_log(audit_path) == (True, 4, None)


def test_refuses_to_append_to_tampered_log(engine: Aegis, audit_path: Path) -> None:
    _fill(engine)
    audit_path.write_text(audit_path.read_text().replace("note", "xxxx", 1))
    with pytest.raises(RuntimeError):
        AuditLog(audit_path)


def test_raw_args_not_stored(engine: Aegis, audit_path: Path) -> None:
    engine.decide(ToolCall(agent_id="bot", tool="note", args={"text": "SUPERSECRETVALUE"}))
    assert "SUPERSECRETVALUE" not in audit_path.read_text()
