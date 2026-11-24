"""HTTP gateway. Agents POST proposed tool calls to /v1/decide and enforce the returned effect."""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ValidationError

from aegis.gateway.approvals import ApprovalStore
from aegis.gateway.audit import AuditLog
from aegis.gateway.engine import Aegis
from aegis.gateway.metrics import Metrics
from aegis.gateway.models import Decision, ToolCall
from aegis.gateway.policy import Policy

log = logging.getLogger("aegis.gateway")

MAX_ARGS_BYTES = 256 * 1024


class DecideRequest(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, Any] = {}
    request_id: str | None = None


def _bearer(authorization: str | None) -> str:
    return (authorization or "").removeprefix("Bearer ").strip()


def create_app(
    policy_path: str | Path,
    audit_path: str | Path,
    *,
    approval_ttl: float = 300.0,
) -> FastAPI:
    policy_path = Path(policy_path)
    metrics = Metrics()
    engine = Aegis(
        Policy.load(policy_path),
        AuditLog(audit_path, fsync=os.environ.get("AEGIS_AUDIT_FSYNC", "1") != "0"),
        approvals=ApprovalStore(ttl=approval_ttl),
        metrics=metrics,
    )
    app = FastAPI(title="Aegis", version="1.2.0", docs_url=None, redoc_url=None)

    def require_admin(authorization: str | None) -> None:
        admin = os.environ.get("AEGIS_ADMIN_TOKEN", "")
        if not admin or not hmac.compare_digest(_bearer(authorization), admin):
            raise HTTPException(status_code=401, detail="authentication failed")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics_endpoint(authorization: str | None = Header(default=None)) -> Response:
        if os.environ.get("AEGIS_METRICS_PUBLIC") != "1":
            require_admin(authorization)
        return Response(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/decide", response_model=Decision)
    def decide(req: DecideRequest, authorization: str | None = Header(default=None)) -> Decision:
        fields = req.model_dump(exclude_none=True)
        try:
            call = ToolCall(**fields)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid request") from exc
        token = _bearer(authorization)
        if not token or not engine.authenticate(call.agent_id, token):
            engine.reject_unauthenticated(call)
            metrics.event("auth_failure")
            raise HTTPException(status_code=401, detail="authentication failed")
        if len(str(call.args)) > MAX_ARGS_BYTES:
            raise HTTPException(status_code=413, detail="arguments too large")
        return engine.decide(call)

    @app.get("/v1/approvals/{approval_id}")
    def approval_status(
        approval_id: str,
        authorization: str | None = Header(default=None),
        x_aegis_agent: str | None = Header(default=None),
    ) -> dict[str, object]:
        """An agent polls this for the outcome of a call that returned `ask`."""
        token = _bearer(authorization)
        if not x_aegis_agent or not token or not engine.authenticate(x_aegis_agent, token):
            raise HTTPException(status_code=401, detail="authentication failed")
        item = engine.approvals.get(approval_id) if engine.approvals else None
        if item is None or item.call.agent_id != x_aegis_agent:
            raise HTTPException(status_code=404, detail="not found")
        return {"id": item.id, "status": item.status}

    @app.get("/v1/admin/approvals")
    def pending_approvals(
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        require_admin(authorization)
        return [a.summary() for a in engine.approvals.pending()] if engine.approvals else []

    @app.post("/v1/admin/approvals/{approval_id}/{action}")
    def resolve_approval(
        approval_id: str,
        action: str,
        authorization: str | None = Header(default=None),
        x_aegis_approver: str | None = Header(default=None),
    ) -> dict[str, object]:
        require_admin(authorization)
        if action not in ("approve", "deny"):
            raise HTTPException(status_code=404, detail="not found")
        try:
            item = engine.resolve_approval(
                approval_id, action == "approve", (x_aegis_approver or "admin")[:64]
            )
        except Exception as exc:  # noqa: BLE001 - audit unwritable: leave pending, fail closed
            log.exception("could not audit approval resolution")
            raise HTTPException(status_code=503, detail="audit unavailable") from exc
        if item is None:
            raise HTTPException(status_code=404, detail="not found or not pending")
        metrics.event("approval", item.status)
        return item.summary()

    @app.post("/v1/admin/reload")
    def reload_policy(authorization: str | None = Header(default=None)) -> dict[str, int]:
        require_admin(authorization)
        try:
            new_policy = Policy.load(policy_path)
        except Exception as exc:  # noqa: BLE001 - keep serving the last good policy
            log.warning("policy reload rejected: %s", exc)
            raise HTTPException(status_code=400, detail="invalid policy; kept previous") from exc
        engine.swap_policy(new_policy)
        metrics.event("policy_reload")
        return {"agents": len(new_policy.agents)}

    return app
