"""Tool-call gateway: policy, risk scoring, rate limiting and tamper-evident audit for AI agents."""

from aegis.gateway.approvals import ApprovalStore
from aegis.gateway.audit import AuditLog, verify_log
from aegis.gateway.engine import Aegis
from aegis.gateway.metrics import Metrics
from aegis.gateway.models import Decision, Effect, ToolCall
from aegis.gateway.policy import Policy

__all__ = [
    "Aegis",
    "ApprovalStore",
    "AuditLog",
    "Decision",
    "Effect",
    "Metrics",
    "Policy",
    "ToolCall",
    "verify_log",
]
