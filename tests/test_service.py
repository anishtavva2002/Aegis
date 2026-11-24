from aegis.service import AegisService

class FakeRunner:
    def run(self, source, policy):
        return {"status": "completed", "exit_code": 0, "output": "ok", "container_id": "fake"}

def test_safe_code_runs_without_approval(tmp_path):
    service = AegisService(FakeRunner(), tmp_path / "audit.jsonl")
    result = service.execute('print("hello")')
    assert result["status"] == "completed"

def test_approval_required_does_not_run_without_approval(tmp_path):
    runner = FakeRunner()
    service = AegisService(runner, tmp_path / "audit.jsonl")
    result = service.execute('eval("1+1")')
    assert result["status"] == "approval_required"

def test_approved_code_runs(tmp_path):
    service = AegisService(FakeRunner(), tmp_path / "audit.jsonl")
    result = service.execute('eval("1+1")', approved=True)
    assert result["status"] == "completed"
