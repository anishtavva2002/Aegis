import argparse
import hashlib
import json
import secrets
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AEGIS: sandbox and AI-agent tool-call gateway")
    parser.add_argument("--audit", default="aegis-audit.jsonl")
    parser.add_argument("--policy", default=None, help="sandbox policy (JSON)")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="Statically inspect a Python file")
    inspect.add_argument("script")
    run = sub.add_parser("run", help="Inspect and execute a Python file in Docker")
    run.add_argument("script")
    run.add_argument("--approve", action="store_true",
                     help="Explicitly approve execution when policy requests approval")

    sub.add_parser("hash-key", help="Generate an agent API key and its sha256 for the policy")
    check = sub.add_parser("check-policy", help="Validate a gateway policy (YAML)")
    check.add_argument("gateway_policy")
    verify = sub.add_parser("verify-log", help="Verify an audit log's hash chain")
    verify.add_argument("log")
    serve = sub.add_parser("serve", help="Run the tool-call gateway")
    serve.add_argument("--gateway-policy", required=True)
    serve.add_argument("--gateway-audit", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command in {"inspect", "run"}:
        from .service import AegisService

        source = Path(args.script).read_text(encoding="utf-8")
        runner = None
        if args.command == "run":  # Docker is only needed to execute, not to inspect
            from .runner import DockerRunner

            runner = DockerRunner()
        service = AegisService(runner, args.audit, args.policy)
        if args.command == "inspect":
            result = service.inspect(source)
        else:
            result = service.execute(source, approved=args.approve)
        print(json.dumps(result, indent=2))
        return 2 if result.get("status") in {"denied", "approval_required", "failed"} else 0

    if args.command == "hash-key":
        key = secrets.token_urlsafe(32)
        print(f"key (give to the agent, shown once): {key}")
        print(f"key_sha256 (put in policy):          {hashlib.sha256(key.encode()).hexdigest()}")
        return 0

    if args.command == "check-policy":
        from .gateway.policy import Policy

        print(f"OK: {len(Policy.load(args.gateway_policy).agents)} agent(s)")
        return 0

    if args.command == "verify-log":
        from .audit import verify_chain
        from .gateway.audit import verify_log

        # Gateway logs carry a "seq" field; sandbox logs do not.
        path = Path(args.log)
        first = path.read_text(encoding="utf-8").splitlines()[:1] if path.exists() else []
        try:
            is_gateway = bool(first) and "seq" in json.loads(first[0])
        except ValueError:
            is_gateway = False  # malformed; verify_chain will report it
        ok, count, error = verify_log(args.log) if is_gateway else verify_chain(args.log)
        print(f"OK: {count} record(s)" if ok else f"TAMPERED after {count} record(s): {error}")
        return 0 if ok else 1

    if args.command == "serve":
        import uvicorn

        from .gateway.app import create_app

        uvicorn.run(create_app(args.gateway_policy, args.gateway_audit),
                    host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
