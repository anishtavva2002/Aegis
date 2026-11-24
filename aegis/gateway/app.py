"""HTTP gateway. Agents POST proposed tool calls to /v1/decide and enforce the returned effect."""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ValidationError

from aegis.gateway.audit import AuditLog
from aegis.gateway.engine import Aegis
from aegis.gateway.models import Decision, ToolCall
from aegis.gateway.policy import Policy

log = logging.getLogger("aegis.gateway")


class DecideRequest(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, object] = {}
    request_id: str | None = None


def create_app(policy_path: str | Path, audit_path: str | Path) -> FastAPI:
    policy_path = Path(policy_path)
    engine = Aegis(Policy.load(policy_path), AuditLog(audit_path))
    app = FastAPI(title="Aegis", version="0.2.0", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/decide", response_model=Decision)
    def decide(req: DecideRequest, authorization: str | None = Header(default=None)) -> Decision:
        fields = req.model_dump(exclude_none=True)
        try:
            call = ToolCall(**fields)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid request") from exc
        token = (authorization or "").removeprefix("Bearer ").strip()
        if not token or not engine.authenticate(call.agent_id, token):
            engine.reject_unauthenticated(call)
            raise HTTPException(status_code=401, detail="authentication failed")
        return engine.decide(call)

    @app.post("/v1/admin/reload")
    def reload_policy(authorization: str | None = Header(default=None)) -> dict[str, int]:
        admin = os.environ.get("AEGIS_ADMIN_TOKEN", "")
        supplied = (authorization or "").removeprefix("Bearer ").strip()
        if not admin or not hmac.compare_digest(supplied, admin):
            raise HTTPException(status_code=401, detail="authentication failed")
        try:
            new_policy = Policy.load(policy_path)
        except Exception as exc:  # noqa: BLE001 - keep serving the last good policy
            log.warning("policy reload rejected: %s", exc)
            raise HTTPException(status_code=400, detail="invalid policy; kept previous") from exc
        engine.swap_policy(new_policy)
        return {"agents": len(new_policy.agents)}

    return app
