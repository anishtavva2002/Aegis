from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

@dataclass
class Analysis:
    findings: list[dict[str, Any]]
    risk_score: int
    decision: Decision
    reasons: list[str]

    def to_dict(self):
        result = asdict(self)
        result["decision"] = self.decision.value
        return result
