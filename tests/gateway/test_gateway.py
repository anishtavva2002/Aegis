from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from aegis.gateway import verify_log
from aegis.gateway.app import create_app

from .conftest import KEY, POLICY

AUTH = {"Authorization": f"Bearer {KEY}"}


@pytest.fixture
def client(policy_path: Path, audit_path: Path) -> TestClient:
    return TestClient(create_app(policy_path, audit_path))


def body(tool: str = "note", **args: object) -> dict[str, object]:
    return {"agent_id": "bot", "tool": tool, "args": args}


def test_health(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_decide_allow(client: TestClient) -> None:
    r = client.post("/v1/decide", json=body(text="hi"), headers=AUTH)
    assert r.status_code == 200 and r.json()["effect"] == "allow"


def test_decide_deny(client: TestClient) -> None:
    r = client.post("/v1/decide", json=body("rm_everything"), headers=AUTH)
    assert r.json()["effect"] == "deny"


def test_missing_or_bad_key_401_and_audited(client: TestClient, audit_path: Path) -> None:
    assert client.post("/v1/decide", json=body()).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert client.post("/v1/decide", json=body(), headers=bad).status_code == 401
    assert verify_log(audit_path)[1] == 2


def test_invalid_body_422(client: TestClient) -> None:
    assert client.post("/v1/decide", json={"tool": "x"}, headers=AUTH).status_code == 422


def test_reload_requires_admin_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AEGIS_ADMIN_TOKEN", raising=False)
    assert client.post("/v1/admin/reload").status_code == 401
    monkeypatch.setenv("AEGIS_ADMIN_TOKEN", "adm")
    assert client.post("/v1/admin/reload", headers={"Authorization": "Bearer x"}).status_code == 401


def test_reload_applies_and_rejects_bad_policy(
    client: TestClient, policy_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_ADMIN_TOKEN", "adm")
    admin = {"Authorization": "Bearer adm"}

    new = {**POLICY, "agents": {"bot": {**POLICY["agents"]["bot"], "tools": {}}}}
    policy_path.write_text(yaml.safe_dump(new))
    assert client.post("/v1/admin/reload", headers=admin).status_code == 200
    assert client.post("/v1/decide", json=body(text="x"), headers=AUTH).json()["effect"] == "deny"

    policy_path.write_text("version: 1\nagents: {bot: {key_sha256: nothex}}")
    assert client.post("/v1/admin/reload", headers=admin).status_code == 400
    # previous (now tool-less) policy still serving
    assert client.post("/v1/decide", json=body(text="x"), headers=AUTH).status_code == 200
