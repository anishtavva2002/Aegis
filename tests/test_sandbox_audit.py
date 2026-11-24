import json

import pytest

from aegis.audit import AuditLogger, verify_chain
from aegis.cli import main


def _log(tmp_path, n=3):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    for i in range(n):
        logger.record({"event": "inspection", "i": i})
    return path


def test_chain_verifies(tmp_path):
    assert verify_chain(_log(tmp_path)) == (True, 3, None)


def test_edit_detected(tmp_path):
    path = _log(tmp_path)
    path.write_text(path.read_text().replace('"i": 1', '"i": 9'))
    assert not verify_chain(path)[0]


def test_deletion_detected(tmp_path):
    path = _log(tmp_path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    assert not verify_chain(path)[0]


def test_restart_continues_chain(tmp_path):
    path = _log(tmp_path, 2)
    AuditLogger(path).record({"event": "execution"})
    assert verify_chain(path) == (True, 3, None)


def test_refuses_tampered_log(tmp_path):
    path = _log(tmp_path)
    path.write_text(path.read_text().replace("inspection", "xxx", 1))
    with pytest.raises(RuntimeError):
        AuditLogger(path)


def test_cli_inspect_needs_no_docker(tmp_path, capsys):
    script = tmp_path / "s.py"
    script.write_text('print("hi")')
    assert main(["--audit", str(tmp_path / "a.jsonl"), "inspect", str(script)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "ALLOW"


def test_cli_verify_log_handles_both_formats(tmp_path):
    assert main(["verify-log", str(_log(tmp_path))]) == 0
