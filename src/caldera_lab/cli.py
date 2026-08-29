from __future__ import annotations

import argparse
import json
import threading
from dataclasses import asdict
from pathlib import Path

from .agent import BeaconAgent
from .beacon import BeaconServer, BeaconState
from .catalog import AbilityCatalog
from .coordinator import Coordinator
from .executor import DockerLabExecutor, DryRunExecutor, ExecutionResult, LocalLabExecutor
from .orchestrator import Event, Orchestrator, now, write_events
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


class _EventSink:
    """Collects beacon events from server threads and appends them to the log."""

    def __init__(self, run_id: str, log_path: Path | None) -> None:
        self.run_id = run_id
        self.log_path = log_path
        self.events: list[Event] = []
        self._lock = threading.Lock()

    def record(self, name: str, details: dict[str, object]) -> None:
        with self._lock:
            self.events.append(Event(now(), self.run_id, name, details))

    def flush(self) -> None:
        if not self.log_path or not self.events:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


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
    policy = LabPolicy()
    coordinator = Coordinator(
        catalog,
        policy=policy,
        planner_mode=args.planner,
        q_table_path=None if args.no_q_table else args.q_table,
        max_steps=args.steps,
    )
    sink = _EventSink(coordinator.run_id, args.log)

    def record(agent_id: str, entry: dict[str, object]) -> None:
        coordinator.record_result(
            ExecutionResult(
                ability_id=str(entry["ability_id"]),
                status=str(entry["status"]),
                stdout=str(entry["stdout"]),
                stderr=str(entry["stderr"]),
                return_code=int(entry["return_code"]),
                isolation=str(entry.get("isolation", "unknown")),
                duration_seconds=float(entry.get("duration_seconds") or 0.0),
            ),
            agent_id=agent_id,
        )

    # The beacon queue is the planner and the RL policy, not a fixed list.
    state = BeaconState(
        catalog,
        on_event=sink.record,
        task_source=coordinator.next_ability,
        result_sink=record,
    )
    failures: list[BaseException] = []

    with BeaconServer(state) as server:
        print(f"beacon listening on {server.url} (token is per-run and not persisted)")
        agents = [
            BeaconAgent(catalog, executor, server.url, server.token, policy)
            for _ in range(args.agents)
        ]

        def drive(agent: BeaconAgent) -> None:
            try:
                agent.run(max_beacons=args.steps + 1)
            except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
                failures.append(exc)

        threads = [threading.Thread(target=drive, args=(agent,)) for agent in agents]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    events = coordinator.finish()
    write_events(events, args.log)
    sink.flush()
    for agent in agents:
        record = state.agents[agent.agent_id]
        print(f"agent {agent.agent_id} ran {len(record.results)} abilities")
        for result in record.results:
            first_line = result["stdout"].splitlines()[0] if result["stdout"] else ""
            print(f"  {result['ability_id']:<26}{result['status']:<12}{first_line[:60]}")
    print(
        f"run {coordinator.run_id}: {len(events)} coordinator + "
        f"{len(sink.events)} beacon events -> {args.log}"
    )
    if failures:
        parser.exit(1, f"{len(failures)} agent(s) failed: {failures[0]}\n")


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
    serve.add_argument("--planner", choices=("rules", "llm", "hybrid"), default="hybrid")
    serve.add_argument("--steps", type=positive_int, default=4)
    serve.add_argument(
        "--agents", type=positive_int, default=1, help="agents beaconing concurrently"
    )
    serve.add_argument("--workspace", type=Path, default=None)
    serve.add_argument("--log", type=Path, default=Path(".runtime/run.jsonl"))
    serve.add_argument("--q-table", type=Path, default=Path(".runtime/q_table.json"))
    serve.add_argument("--no-q-table", action="store_true")
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
