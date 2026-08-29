from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .catalog import AbilityCatalog
from .executor import Executor
from .planner import LLMPlanner, Plan, RulePlanner
from .policy import LabPolicy
from .rl import QPolicy


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    timestamp: str
    run_id: str
    event: str
    details: dict[str, object]


class Orchestrator:
    def __init__(
        self,
        catalog: AbilityCatalog,
        executor: Executor,
        policy: LabPolicy | None = None,
        planner_mode: str = "hybrid",
        seed: int = 7,
        q_table_path: Path | None = None,
    ) -> None:
        self.catalog = catalog
        self.executor = executor
        self.policy = policy or LabPolicy()
        self.planner = (
            LLMPlanner(catalog) if planner_mode in {"llm", "hybrid"} else RulePlanner(catalog)
        )
        self.rl = QPolicy(catalog, seed=seed)
        self.run_id = uuid.uuid4().hex[:12]
        self.q_table_path = q_table_path
        self.q_table_loaded = bool(q_table_path and self.rl.load(q_table_path))

    def run(self, steps: int, log_path: Path | None = None) -> list[Event]:
        limit = min(steps, self.policy.max_steps)
        observations: tuple[str, ...] = ()
        used: set[str] = set()
        events: list[Event] = []
        plan: Plan = self.planner.plan(observations, limit)
        events.append(
            Event(
                now(),
                self.run_id,
                "plan.created",
                {
                    "source": plan.source,
                    "rationale": plan.rationale,
                    "abilities": plan.ability_ids,
                },
            )
        )
        events.append(
            Event(
                now(),
                self.run_id,
                "rl.loaded",
                {
                    "path": str(self.q_table_path) if self.q_table_path else None,
                    "restored": self.q_table_loaded,
                    "entries": len(self.rl.q),
                },
            )
        )
        for index in range(limit):
            candidates = tuple(
                item
                for item in plan.ability_ids
                if item in self.catalog.ids() and item not in used
            )
            if not candidates:
                candidates = tuple(item for item in self.catalog.ids() if item not in used)
            if not candidates:
                used.clear()
                candidates = self.catalog.ids()
            if not candidates:
                break
            state = self.rl.state(observations)
            ability_id = self.rl.choose(state, candidates)
            used.add(ability_id)
            self.policy.validate(self.catalog, ability_id, index)
            ability = self.catalog.get(ability_id)
            events.append(
                Event(
                    now(),
                    self.run_id,
                    "ability.approved",
                    {
                        "index": index,
                        "ability_id": ability.id,
                        "technique": ability.technique,
                    },
                )
            )
            result = self.executor.execute(ability, self.policy)
            events.append(Event(now(), self.run_id, "ability.completed", asdict(result)))
            observations = (*observations, f"{ability.id}:{result.status}:{result.return_code}")
            reward = 1.0 if result.status in {"succeeded", "planned"} else -1.0
            self.rl.update(state, ability_id, reward, self.rl.state(observations))
            remaining = limit - index - 1
            if remaining:
                plan = self.planner.plan(observations, remaining)
        if self.q_table_path:
            self.rl.save(self.q_table_path)
            events.append(
                Event(
                    now(),
                    self.run_id,
                    "rl.saved",
                    {"path": str(self.q_table_path), "entries": len(self.rl.q)},
                )
            )
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                for item in events:
                    handle.write(json.dumps(asdict(item), ensure_ascii=False) + "\n")
        return events
