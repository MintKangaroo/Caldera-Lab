from __future__ import annotations

import argparse
from pathlib import Path

from .catalog import AbilityCatalog
from .executor import DockerLabExecutor, DryRunExecutor, LocalLabExecutor
from .orchestrator import Orchestrator

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "catalog" / "abilities.json"


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("--steps must be at least 1")
    return number


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Constrained AI/RL Caldera lab")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="plan and execute an isolated lab run")
    run.add_argument("--executor", choices=("docker", "local", "dry-run"), default="docker")
    run.add_argument("--planner", choices=("rules", "llm", "hybrid"), default="hybrid")
    run.add_argument("--steps", type=positive_int, default=4)
    run.add_argument("--log", type=Path, default=Path(".runtime/run.jsonl"))
    run.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="directory bind-mounted read-only at /workspace inside the agent",
    )
    run.add_argument(
        "--allow-local", action="store_true", help="explicitly allow the development executor"
    )
    args = parser.parse_args(argv)
    if args.command != "run":
        return
    catalog = AbilityCatalog.from_json(CATALOG)
    if args.executor == "docker":
        executor = DockerLabExecutor(workspace=args.workspace)
    elif args.executor == "dry-run":
        executor = DryRunExecutor()
    elif args.allow_local:
        executor = LocalLabExecutor()
    else:
        parser.error("--executor local requires --allow-local")
    events = Orchestrator(catalog, executor, planner_mode=args.planner).run(args.steps, args.log)
    for event in events:
        print(f"{event.timestamp} {event.event} {event.details}")
