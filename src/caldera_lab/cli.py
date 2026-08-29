from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent import BeaconAgent
from .beacon import BeaconServer, BeaconState
from .catalog import AbilityCatalog
from .executor import DockerLabExecutor, DryRunExecutor, LocalLabExecutor
from .orchestrator import Orchestrator
from .policy import LabPolicy
from .report import coverage, load_events, render, summarize

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "catalog" / "abilities.json"


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("--steps must be at least 1")
    return number


def _report(
    parser: argparse.ArgumentParser, catalog: AbilityCatalog, args: argparse.Namespace
) -> None:
    if not args.log.exists():
        parser.error(f"audit log not found: {args.log}")
    runs = summarize(load_events(args.log))
    if args.json:
        print(
            json.dumps(
                {
                    "runs": {run_id: summary.as_dict() for run_id, summary in runs.items()},
                    "coverage": coverage(catalog, runs),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    print(render(catalog, runs))


def _build_executor(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> DockerLabExecutor | DryRunExecutor | LocalLabExecutor:
    if args.executor == "docker":
        return DockerLabExecutor(workspace=getattr(args, "workspace", None))
    if args.executor == "dry-run":
        return DryRunExecutor()
    if getattr(args, "allow_local", False):
        return LocalLabExecutor()
    parser.error("--executor local requires --allow-local")
    raise AssertionError("unreachable")


def _serve(
    parser: argparse.ArgumentParser, catalog: AbilityCatalog, args: argparse.Namespace
) -> None:
    executor = _build_executor(parser, args)
    queue = catalog.ids()[: args.steps]
    state = BeaconState(catalog, queue=queue)
    with BeaconServer(state) as server:
        print(f"beacon listening on {server.url} (token is per-run and not persisted)")
        agent = BeaconAgent(catalog, executor, server.url, server.token, LabPolicy())
        executed = agent.run(max_beacons=args.steps + 1)
        record = state.agents[agent.agent_id]
        print(f"agent {agent.agent_id} executed {len(executed)} abilities")
        for result in record.results:
            first_line = result["stdout"].splitlines()[0] if result["stdout"] else ""
            print(f"  {result['ability_id']:<26}{result['status']:<12}{first_line[:60]}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Constrained AI/RL Caldera lab")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="plan and execute an isolated lab run")
    run.add_argument("--executor", choices=("docker", "local", "dry-run"), default="docker")
    run.add_argument("--planner", choices=("rules", "llm", "hybrid"), default="hybrid")
    run.add_argument("--steps", type=positive_int, default=4)
    run.add_argument("--log", type=Path, default=Path(".runtime/run.jsonl"))
    run.add_argument(
        "--q-table",
        type=Path,
        default=Path(".runtime/q_table.json"),
        help="JSON file the RL policy is loaded from and saved to",
    )
    run.add_argument(
        "--no-q-table", action="store_true", help="run without loading or saving RL state"
    )
    run.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="directory bind-mounted read-only at /workspace inside the agent",
    )
    run.add_argument(
        "--allow-local", action="store_true", help="explicitly allow the development executor"
    )
    serve = sub.add_parser(
        "serve", help="run the loopback beacon server and drive one agent through it"
    )
    serve.add_argument("--executor", choices=("docker", "local", "dry-run"), default="docker")
    serve.add_argument("--steps", type=positive_int, default=4)
    serve.add_argument("--workspace", type=Path, default=None)
    serve.add_argument("--allow-local", action="store_true")

    report = sub.add_parser("report", help="summarise an audit log")
    report.add_argument("--log", type=Path, default=Path(".runtime/run.jsonl"))
    report.add_argument(
        "--json", action="store_true", help="emit machine-readable output instead of a table"
    )

    args = parser.parse_args(argv)
    catalog = AbilityCatalog.from_json(CATALOG)
    if args.command == "report":
        _report(parser, catalog, args)
        return
    if args.command == "serve":
        _serve(parser, catalog, args)
        return
    if args.command != "run":
        return
    executor = _build_executor(parser, args)
    orchestrator = Orchestrator(
        catalog,
        executor,
        planner_mode=args.planner,
        q_table_path=None if args.no_q_table else args.q_table,
    )
    events = orchestrator.run(args.steps, args.log)
    for event in events:
        print(f"{event.timestamp} {event.event} {event.details}")
