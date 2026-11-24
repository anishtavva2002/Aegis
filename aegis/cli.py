import argparse
import json
from pathlib import Path
from .runner import DockerRunner
from .service import AegisService

def main():
    parser = argparse.ArgumentParser(description="AEGIS policy-based execution sandbox")
    parser.add_argument("--audit", default="aegis-audit.jsonl")
    parser.add_argument("--policy", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Statically inspect a Python file")
    inspect.add_argument("script")
    run = sub.add_parser("run", help="Inspect and execute a Python file in Docker")
    run.add_argument("script")
    run.add_argument("--approve", action="store_true",
                     help="Explicitly approve execution when policy requests approval")
    args = parser.parse_args()
    source = Path(args.script).read_text(encoding="utf-8")
    service = AegisService(DockerRunner(), args.audit, args.policy)
    if args.command == "inspect":
        result = service.inspect(source)
    else:
        result = service.execute(source, approved=args.approve)
    print(json.dumps(result, indent=2))
    if result.get("status") in {"denied", "approval_required", "failed"}:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
