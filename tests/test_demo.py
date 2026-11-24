import runpy
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1] / "examples" / "rogue_agent_demo.py"


def test_every_attack_is_handled_as_policy_requires(tmp_path):
    results = runpy.run_path(str(DEMO))["run_scenarios"](tmp_path)
    assert len(results) >= 14
    failures = [r for r in results if not r["ok"]]
    assert not failures, failures


def test_demo_covers_deny_ask_and_tamper(tmp_path):
    results = runpy.run_path(str(DEMO))["run_scenarios"](tmp_path)
    effects = {r["effect"] for r in results}
    assert {"allow", "deny", "ask", "detected"} <= effects
