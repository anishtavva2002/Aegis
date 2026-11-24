"""Single decision point: authenticate -> policy -> risk -> rate limit -> audit. Fails closed."""

from __future__ import annotations

import hashlib
import hmac
import logging

from aegis.analyzer import ScriptAnalyzer
from aegis.gateway import risk
from aegis.gateway.audit import AuditLog
from aegis.gateway.models import Decision, Effect, ToolCall
from aegis.gateway.policy import Policy
from aegis.gateway.ratelimit import TokenBucket

log = logging.getLogger("aegis")


class Aegis:
    def __init__(self, policy: Policy, audit: AuditLog, limiter: TokenBucket | None = None) -> None:
        self._policy = policy
        self._audit = audit
        self._limiter = limiter or TokenBucket()
        self._analyzer = ScriptAnalyzer()

    # -- policy lifecycle -------------------------------------------------
    @property
    def policy(self) -> Policy:
        return self._policy

    def swap_policy(self, policy: Policy) -> None:
        self._policy = policy  # atomic reference swap; in-flight calls keep the old object

    # -- authentication ---------------------------------------------------
    def authenticate(self, agent_id: str, api_key: str) -> bool:
        agent = self._policy.agents.get(agent_id)
        supplied = hashlib.sha256(api_key.encode()).hexdigest()
        expected = agent.key_sha256 if agent else "0" * 64  # constant-time even if unknown
        return hmac.compare_digest(supplied, expected) and agent is not None

    # -- decision ---------------------------------------------------------
    def decide(self, call: ToolCall) -> Decision:
        try:
            decision = self._evaluate(call)
        except Exception:  # noqa: BLE001 - any failure must deny
            log.exception("evaluation failed; denying")
            decision = self._deny(call, "internal error (fail-closed)", "fail_closed")
        return self._record(call, decision)

    def reject_unauthenticated(self, call: ToolCall) -> Decision:
        return self._record(call, self._deny(call, "authentication failed", "authn"))

    def _record(self, call: ToolCall, decision: Decision) -> Decision:
        try:
            self._audit.append(call, decision)
        except Exception:  # noqa: BLE001
            log.exception("audit write failed; denying")
            return self._deny(call, "audit unavailable (fail-closed)", "audit_down")
        return decision

    @staticmethod
    def _deny(call: ToolCall, reason: str, rule: str, risk_score: int = 0) -> Decision:
        return Decision(
            effect=Effect.DENY, reason=reason, rule=rule, risk=risk_score,
            request_id=call.request_id,
        )

    def _evaluate(self, call: ToolCall) -> Decision:
        policy = self._policy
        agent = policy.agents.get(call.agent_id)
        if agent is None:
            return self._deny(call, f"unknown agent {call.agent_id!r}", "unknown_agent")

        rule = agent.tools.get(call.tool)
        if rule is None:
            return self._deny(call, f"tool {call.tool!r} not permitted", "tool_not_allowed")

        for name, value in call.args.items():
            constraint = rule.constraints.get(name)
            if constraint is None:
                if not rule.allow_extra_args:
                    return self._deny(call, f"argument {name!r} not declared", "undeclared_arg")
                continue
            problem = constraint.violation(value)
            if problem:
                return self._deny(call, f"argument {name!r}: {problem}", "arg_constraint")
        for name, constraint in rule.constraints.items():
            if constraint.required and name not in call.args:
                return self._deny(call, f"missing required argument {name!r}", "arg_required")

        score, labels = risk.score(call.args)
        for name, constraint in rule.constraints.items():
            value = call.args.get(name)
            if constraint.analyze_python and isinstance(value, str):
                analysis = self._analyzer.analyze_text(value)
                if analysis.risk_score > 0:
                    rules = sorted({f["rule"] for f in analysis.findings})
                    labels = sorted({*labels, *(f"python:{r}" for r in rules)})
                score = max(score, analysis.risk_score)
        if score >= policy.risk.deny_threshold:
            return self._deny(call, f"high risk: {', '.join(labels)}", "risk_deny", score)

        if not self._limiter.allow(call.agent_id, agent.rate_limit.per_minute):
            return self._deny(call, "rate limit exceeded", "rate_limit", score)

        if rule.effect == "ask" or score >= policy.risk.ask_threshold:
            why = "tool requires approval" if rule.effect == "ask" else ", ".join(labels)
            return Decision(
                effect=Effect.ASK, reason=f"approval needed: {why}", rule="ask",
                risk=score, request_id=call.request_id,
            )
        return Decision(
            effect=Effect.ALLOW, reason="permitted by policy", rule="allow",
            risk=score, request_id=call.request_id,
        )
