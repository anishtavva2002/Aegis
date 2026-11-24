from pathlib import Path
from .analyzer import ScriptAnalyzer
from .policy import PolicyEngine
from .audit import AuditLogger
from .models import Decision

class AegisService:
    def __init__(self, runner, audit_path, policy_path=None):
        self.analyzer = ScriptAnalyzer()
        self.policy = PolicyEngine(policy_path)
        self.runner = runner
        self.audit = AuditLogger(Path(audit_path))

    def inspect(self, source: str):
        analysis = self.analyzer.analyze_text(source)
        decision = self.policy.decide(analysis.risk_score, analysis.decision)
        result = analysis.to_dict()
        result["decision"] = decision.value
        self.audit.record({"event": "inspection", "decision": decision.value,
                           "risk_score": analysis.risk_score,
                           "findings": analysis.findings})
        return result

    def execute(self, source: str, approved=False):
        inspection = self.inspect(source)
        decision = Decision(inspection["decision"])
        if decision == Decision.DENY:
            return {"status": "denied", "inspection": inspection}
        if decision == Decision.APPROVAL_REQUIRED and not approved:
            return {"status": "approval_required", "inspection": inspection}
        result = self.runner.run(source, self.policy.policy)
        self.audit.record({"event": "execution", "decision": decision.value,
                           "status": result["status"], "exit_code": result["exit_code"]})
        return {"status": result["status"], "inspection": inspection, "execution": result}
