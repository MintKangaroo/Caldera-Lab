from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .catalog import AbilityCatalog
from .executor import ExecutionResult
from .planner import LLMPlanner, Plan, RulePlanner
from .policy import LabPolicy
from .reward import RewardModel
from .rl import QPolicy


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    timestamp: str
    run_id: str
    event: str
    details: dict[str, object]


class Coordinator:
    """Decides what runs next and learns from what came back.

    Both execution paths go through this: the sequential orchestrator and the
    beacon server handing work to agents. Keeping one decision point is the
    reason the beacon queue is not a second, dumber planner.
    """

    def __init__(
        self,
        catalog: AbilityCatalog,
        policy: LabPolicy | None = None,
        planner_mode: str = "hybrid",
        seed: int = 7,
        q_table_path: Path | None = None,
        reward_model: RewardModel | None = None,
        max_steps: int | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy or LabPolicy()
        self.planner = (
            LLMPlanner(catalog) if planner_mode in {"llm", "hybrid"} else RulePlanner(catalog)
        )
        self.rl = QPolicy(catalog, seed=seed)
        self.reward_model = reward_model or RewardModel()
        self.run_id = uuid.uuid4().hex[:12]
        self.q_table_path = q_table_path
        self.q_table_loaded = bool(q_table_path and self.rl.load(q_table_path))

        self.limit = min(max_steps or self.policy.max_steps, self.policy.max_steps)
        self.events: list[Event] = []
        self._lock = threading.Lock()
        self._observations: tuple[str, ...] = ()
        self._used: set[str] = set()
        self._issued = 0
        self._pending: dict[str, tuple[str, str]] = {}
        self._started = False

    def _emit(self, name: str, details: dict[str, object]) -> None:
        self.events.append(Event(now(), self.run_id, name, details))

    def start(self) -> None:
        """Plan once up front and record the starting conditions."""
        with self._lock:
            if self._started:
                return
            self._started = True
            self.reward_model.reset()
            plan = self.planner.plan(self._observations, self.limit)
            self._plan = plan
            self._emit(
                "plan.created",
                {
                    "source": plan.source,
                    "rationale": plan.rationale,
                    "abilities": plan.ability_ids,
                    "diagnostics": plan.diagnostics,
                },
            )
            self._emit(
                "rl.loaded",
                {
                    "path": str(self.q_table_path) if self.q_table_path else None,
                    "restored": self.q_table_loaded,
                    "entries": len(self.rl.q),
                },
            )

    def _candidates(self) -> tuple[str, ...]:
        plan: Plan = self._plan
        candidates = tuple(
            item
            for item in plan.ability_ids
            if item in self.catalog.ids() and item not in self._used
        )
        if not candidates:
            candidates = tuple(item for item in self.catalog.ids() if item not in self._used)
        if not candidates:
            self._used.clear()
            candidates = self.catalog.ids()
        return candidates

    def next_ability(self, agent_id: str = "local") -> str | None:
        """Hand out the next ability, or None when the budget is spent.

        Safe to call from several agent threads: selection, the used set, and
        the step budget all move under one lock.
        """
        self.start()
        with self._lock:
            if self._issued >= self.limit:
                return None
            candidates = self._candidates()
            if not candidates:
                return None
            index = self._issued
            state = self.rl.state(self._observations)
            ability_id = self.rl.choose(state, candidates)
            self.policy.validate(self.catalog, ability_id, index)
            self._used.add(ability_id)
            self._issued += 1
            self._pending[f"{agent_id}:{ability_id}"] = (state, ability_id)
            ability = self.catalog.get(ability_id)
            self._emit(
                "ability.approved",
                {
                    "index": index,
                    "agent_id": agent_id,
                    "ability_id": ability.id,
                    "technique": ability.technique,
                },
            )
            return ability_id

    def record_result(self, result: ExecutionResult, agent_id: str = "local") -> None:
        """Score a result, update the policy, and replan for what is left."""
        with self._lock:
            key = f"{agent_id}:{result.ability_id}"
            state, ability_id = self._pending.pop(
                key, (self.rl.state(self._observations), result.ability_id)
            )
            ability = self.catalog.get(ability_id)
            self._emit("ability.completed", {"agent_id": agent_id, **asdict(result)})
            self._observations = (
                *self._observations,
                f"{ability_id}:{result.status}:{result.return_code}",
            )
            breakdown = self.reward_model.score(result, self.policy, ability)
            self._emit(
                "reward.scored",
                {"agent_id": agent_id, "ability_id": ability_id, **breakdown.as_details()},
            )
            self.rl.update(state, ability_id, breakdown.total, self.rl.state(self._observations))
            remaining = self.limit - self._issued
            if remaining > 0:
                plan = self.planner.plan(self._observations, remaining)
                self._plan = plan
                if plan.diagnostics:
                    self._emit(
                        "plan.replanned",
                        {
                            "index": self._issued,
                            "source": plan.source,
                            "abilities": plan.ability_ids,
                            "diagnostics": plan.diagnostics,
                        },
                    )

    def finish(self) -> list[Event]:
        with self._lock:
            if self.q_table_path:
                self.rl.save(self.q_table_path)
                self._emit(
                    "rl.saved",
                    {"path": str(self.q_table_path), "entries": len(self.rl.q)},
                )
            return list(self.events)
