from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .catalog import AbilityCatalog
from .coordinator import Coordinator, Event, now
from .executor import Executor
from .policy import LabPolicy
from .reward import RewardModel

__all__ = ["Event", "Orchestrator", "now", "write_events"]


def write_events(events: list[Event], log_path: Path | None) -> None:
    """Append events to the JSONL audit log, preserving earlier runs."""
    if not log_path or not events:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


class Orchestrator:
    """Runs abilities sequentially in this process, via the shared Coordinator."""

    def __init__(
        self,
        catalog: AbilityCatalog,
        executor: Executor,
        policy: LabPolicy | None = None,
        planner_mode: str = "hybrid",
        seed: int = 7,
        q_table_path: Path | None = None,
        reward_model: RewardModel | None = None,
    ) -> None:
        self.catalog = catalog
        self.executor = executor
        self.policy = policy or LabPolicy()
        self.coordinator = Coordinator(
            catalog,
            policy=self.policy,
            planner_mode=planner_mode,
            seed=seed,
            q_table_path=q_table_path,
            reward_model=reward_model,
        )

    @property
    def run_id(self) -> str:
        return self.coordinator.run_id

    @property
    def rl(self):  # noqa: ANN201 - passthrough for callers inspecting the policy
        return self.coordinator.rl

    @property
    def q_table_loaded(self) -> bool:
        return self.coordinator.q_table_loaded

    def run(self, steps: int, log_path: Path | None = None) -> list[Event]:
        self.coordinator.limit = min(steps, self.policy.max_steps)
        self.coordinator.start()
        while True:
            ability_id = self.coordinator.next_ability()
            if ability_id is None:
                break
            result = self.executor.execute(self.catalog.get(ability_id), self.policy)
            self.coordinator.record_result(result)
        events = self.coordinator.finish()
        write_events(events, log_path)
        return events
