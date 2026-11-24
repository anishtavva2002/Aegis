"""stdio MCP proxy.

Sits between an MCP client (the agent) and an MCP server subprocess:

    agent  <--stdio-->  aegis mcp-proxy  <--stdio-->  real MCP server

- `tools/call` requests are decided by the Aegis engine; blocked calls never reach the server.
- `tools/list` responses are filtered to the tools this agent may use.
- Tool results are scanned: secrets are redacted and (optionally) injection text is blocked.
- Anything that cannot be understood is rejected rather than forwarded (fail-closed).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from pydantic import ValidationError

from aegis.gateway import risk
from aegis.gateway.engine import Aegis
from aegis.gateway.models import Decision, Effect, ToolCall

BLOCKED = -32001
INVALID_PARAMS = -32602
PARSE_ERROR = -32700

Approver = Callable[[ToolCall, Decision], bool]


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _map_strings(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: _map_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_map_strings(v, fn) for v in value]
    return value


def _collect_strings(value: Any) -> list[str]:
    out: list[str] = []
    _map_strings(value, lambda s: (out.append(s), s)[1])
    return out


class McpGuard:
    """Pure message-level logic, independent of how bytes are moved."""

    def __init__(
        self,
        engine: Aegis,
        agent_id: str,
        approver: Approver | None = None,
        redact: bool = True,
        block_injection: bool = False,
    ) -> None:
        self.engine = engine
        self.agent_id = agent_id
        self.approver = approver
        self.redact = redact
        self.block_injection = block_injection
        self._lock = threading.Lock()
        self._list_ids: set[Any] = set()
        self._call_ids: dict[Any, str] = {}

    # -- client -> server -------------------------------------------------
    def handle_client_message(self, msg: Any) -> tuple[Any | None, dict[str, Any] | None]:
        """Return (message_to_forward, reply_to_client). Either may be None."""
        if not isinstance(msg, dict):
            return None, _error(None, -32600, "invalid request")
        msg_id = msg.get("id")
        is_request = "id" in msg
        method = msg.get("method")

        if method == "tools/call":
            return self._gate_call(msg, msg_id, is_request)
        if method == "tools/list" and is_request:
            with self._lock:
                self._list_ids.add(msg_id)
        return msg, None

    def _gate_call(
        self, msg: dict[str, Any], msg_id: Any, is_request: bool
    ) -> tuple[Any | None, dict[str, Any] | None]:
        def refuse(code: int, text: str) -> tuple[None, dict[str, Any] | None]:
            return None, (_error(msg_id, code, text) if is_request else None)

        params = msg.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return refuse(INVALID_PARAMS, "tools/call requires params.name")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return refuse(INVALID_PARAMS, "tools/call arguments must be an object")
        try:
            call = ToolCall(agent_id=self.agent_id, tool=params["name"], args=arguments)
        except ValidationError:
            return refuse(INVALID_PARAMS, "invalid tool call")

        decision = self.engine.decide(call)
        allowed = decision.effect == Effect.ALLOW
        if decision.effect == Effect.ASK:
            allowed = self._ask(call, decision)
            if not allowed:
                return refuse(BLOCKED, f"Blocked by Aegis: {decision.reason} (not approved)")
        elif not allowed:
            return refuse(BLOCKED, f"Blocked by Aegis: {decision.reason}")

        if is_request:
            with self._lock:
                self._call_ids[msg_id] = call.tool
        return msg, None

    def _ask(self, call: ToolCall, decision: Decision) -> bool:
        if self.approver is None:
            return False
        try:
            approved = bool(self.approver(call, decision))
            verdict = Decision(
                effect=Effect.ALLOW if approved else Effect.DENY,
                reason="approved interactively" if approved else "declined interactively",
                rule="approval_granted" if approved else "approval_denied",
                request_id=call.request_id,
                approval_id=decision.approval_id,
            )
            self.engine.audit(call, verdict)  # an unwritable audit log means no approval
            return approved
        except Exception:  # noqa: BLE001 - fail closed
            return False

    # -- server -> client -------------------------------------------------
    def handle_server_message(self, msg: Any) -> Any | None:
        if not isinstance(msg, dict) or "id" not in msg or "result" not in msg:
            return msg
        msg_id = msg["id"]
        try:
            with self._lock:
                is_list = msg_id in self._list_ids
                self._list_ids.discard(msg_id)
                tool = self._call_ids.pop(msg_id, None)
        except TypeError:  # unhashable id from a misbehaving server
            return _error(None, BLOCKED, "malformed response blocked by Aegis")
        if is_list:
            return self._filter_tools(msg)
        if tool is not None:
            return self._scan_result(msg, tool)
        return msg

    def _filter_tools(self, msg: dict[str, Any]) -> dict[str, Any]:
        agent = self.engine.policy.agents.get(self.agent_id)
        permitted = set(agent.tools) if agent else set()
        result = msg.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            kept = [t for t in result["tools"] if isinstance(t, dict) and t.get("name") in permitted]
            msg = {**msg, "result": {**result, "tools": kept}}
        return msg

    def _scan_result(self, msg: dict[str, Any], tool: str) -> dict[str, Any]:
        result = msg["result"]
        texts = _collect_strings(result)
        try:
            if self.block_injection and any(risk.has_injection(t) for t in texts):
                self._audit_output(tool, Effect.DENY, "output_blocked", "possible prompt injection")
                return _error(msg["id"], BLOCKED, "tool output blocked by Aegis: possible injection")
            if self.redact:
                count = 0

                def clean(s: str) -> str:
                    nonlocal count
                    cleaned, n = risk.redact(s)
                    count += n
                    return cleaned

                result = _map_strings(result, clean)
                if count:
                    self._audit_output(
                        tool, Effect.ALLOW, "output_redacted", f"{count} secret(s) redacted"
                    )
                    return {**msg, "result": result}
        except Exception:  # noqa: BLE001 - cannot audit/scan: do not pass the output through
            return _error(msg["id"], BLOCKED, "tool output blocked by Aegis: scan failed")
        return msg

    def _audit_output(self, tool: str, effect: Effect, rule: str, reason: str) -> None:
        call = ToolCall(agent_id=self.agent_id, tool=tool)
        self.engine.audit(call, Decision(effect=effect, reason=reason, rule=rule))


# -- transport ------------------------------------------------------------
def run_stdio_proxy(
    guard: McpGuard,
    server_cmd: list[str],
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
) -> int:
    client_in = stdin or sys.stdin
    client_out = stdout or sys.stdout
    proc = subprocess.Popen(  # noqa: S603 - the command is chosen by the operator
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None
    out_lock = threading.Lock()

    def emit(obj: Any) -> None:
        with out_lock:
            client_out.write(json.dumps(obj, separators=(",", ":")) + "\n")
            client_out.flush()

    def to_server(obj: Any) -> bool:
        try:
            proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")  # type: ignore[union-attr]
            proc.stdin.flush()  # type: ignore[union-attr]
            return True
        except (BrokenPipeError, OSError):
            return False

    def pump_server() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                print("[aegis] dropped non-JSON line from server", file=sys.stderr)
                continue
            if isinstance(msg, list):
                out = [m for m in (guard.handle_server_message(x) for x in msg) if m is not None]
                if out:
                    emit(out)
            else:
                filtered = guard.handle_server_message(msg)
                if filtered is not None:
                    emit(filtered)

    reader = threading.Thread(target=pump_server, daemon=True)
    reader.start()

    for line in client_in:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            emit(_error(None, PARSE_ERROR, "parse error"))
            continue
        items = msg if isinstance(msg, list) else [msg]
        forward: list[Any] = []
        for item in items:
            fwd, reply = guard.handle_client_message(item)
            if reply is not None:
                emit(reply)
            if fwd is not None:
                forward.append(fwd)
        if forward and not to_server(forward if isinstance(msg, list) else forward[0]):
            break

    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=5)
    reader.join(timeout=5)
    return proc.returncode or 0


def tty_approver(call: ToolCall, decision: Decision) -> bool:
    """Ask the human at the terminal. No terminal means no approval."""
    path = "CON" if os.name == "nt" else "/dev/tty"
    try:
        with open(path, "r+", encoding="utf-8") as tty:  # noqa: PTH123
            shown = json.dumps(call.args)[:300]
            tty.write(f"\n[aegis] {call.agent_id} wants {call.tool} {shown}\n")
            tty.write(f"[aegis] reason: {decision.reason}. Allow? [y/N] ")
            tty.flush()
            return tty.readline().strip().lower() in {"y", "yes"}
    except OSError:
        return False
