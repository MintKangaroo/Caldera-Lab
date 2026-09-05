from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .catalog import AbilityCatalog
from .clock import now
from .executor import SUCCESS_STATUSES, ExecutionResult
from .facts import FactStore, bind, extract
from .planner import LLMPlanner, Plan, RulePlanner
from .policy import LabPolicy
from .reward import RewardModel
from .rl import CLEAN, DEGRADED, QPolicy


@dataclass(frozen=True)
class Assignment:
    """What an agent is told to run: an ability id and the values it needs.

    The command itself never travels. The agent rebuilds it from its own
    catalog and re-validates every value against its own trait patterns, so a
    binding cannot introduce anything the catalog does not already allow.
    """

    ability_id: str
    bindings: dict[str, str]


@dataclass(frozen=True)
class Event:
    timestamp: str
    run_id: str
    event: str
    details: dict[str, object]


def _permitted(policy: LabPolicy, catalog: AbilityCatalog, ability_id: str, index: int) -> bool:
    try:
        policy.validate(catalog, ability_id, index)
    except PermissionError:
        return False
    return True


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
        agent_policies: dict[str, LabPolicy] | None = None,
        state_mode: str | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy or LabPolicy()
        # An agent may be held to a narrower policy than the lab default, so a
        # less trusted agent cannot be handed everything the catalog allows.
        self.agent_policies: dict[str, LabPolicy] = dict(agent_policies or {})
        self.planner = (
            LLMPlanner(catalog) if planner_mode in {"llm", "hybrid"} else RulePlanner(catalog)
        )
        self.rl = (
            QPolicy(catalog, seed=seed)
            if state_mode is None
            else QPolicy(catalog, seed=seed, state_mode=state_mode)
        )
        self.reward_model = reward_model or RewardModel()
        self.run_id = uuid.uuid4().hex[:12]
        self.q_table_path = q_table_path
        self.q_table_loaded = bool(q_table_path and self.rl.load(q_table_path))

        self.limit = min(max_steps or self.policy.max_steps, self.policy.max_steps)
        self.events: list[Event] = []
        self._lock = threading.Lock()
        self._observations: tuple[str, ...] = ()
        self._used: set[str] = set()
        self._outcome = CLEAN
        self._issued = 0
        self._pending: dict[str, tuple[str, str]] = {}
        self._started = False
        # Facts unlock abilities, which is what makes the order of a run matter.
        self.facts = FactStore()

    def _scarce_for_others(self, agent_id: str, candidates: tuple[str, ...]) -> set[str]:
        """Abilities another declared agent has almost no alternative to.

        A restricted agent is starved whenever an unrestricted one happens to
        take the single ability its policy allows. Nothing forbids that - the
        budget is shared - but it makes a declared policy pointless in
        practice, so an agent with alternatives yields those scarce ones.
        """
        scarce: set[str] = set()
        for other, policy in self.agent_policies.items():
            if other == agent_id:
                continue
            options = [
                item for item in candidates if _permitted(policy, self.catalog, item, 0)
            ]
            if len(options) <= 1:
                scarce.update(options)
        return scarce

    def policy_for(self, agent_id: str) -> LabPolicy:
        return self.agent_policies.get(agent_id, self.policy)

    def set_agent_policy(self, agent_id: str, policy: LabPolicy) -> None:
        with self._lock:
            self.agent_policies[agent_id] = policy

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

    def _state(self) -> str:
        """The state the policy sees. Callers hold the lock."""
        return self.rl.state_from(
            frozenset(self._used),
            self._outcome,
            traits=self.facts.traits(),
            step=self._issued,
        )

    def _available(self, ability_id: str) -> bool:
        """Whether the facts discovered so far unlock this ability."""
        return self.facts.satisfies(self.catalog.get(ability_id))

    def _candidates(self) -> tuple[str, ...]:
        """Everything that could run now, with the plan's suggestions first.

        The plan orders the choice; it does not bound it. Treating it as the
        only source made it an exclusive whitelist: the rule planner proposes a
        fixed catalog prefix that shrinks as the budget is spent, so work
        unlocked mid-run was never offered and the policy was often left with a
        single option. Ordering still gives the planner its say, because equal
        Q values are broken by candidate order.
        """
        plan: Plan = self._plan
        suggested = [
            item
            for item in plan.ability_ids
            if item in self.catalog.ids() and item not in self._used
        ]
        rest = [
            item
            for item in self.catalog.ids()
            if item not in self._used and item not in suggested
        ]
        candidates = suggested + rest
        if not candidates:
            self._used.clear()
            candidates = list(self.catalog.ids())
        # Applied last so it can never be bypassed: an ability whose
        # preconditions are unmet has no command to run.
        return tuple(item for item in candidates if self._available(item))

    def next_ability(self, agent_id: str = "local") -> str | None:
        assignment = self.next_assignment(agent_id)
        return assignment.ability_id if assignment else None

    def next_assignment(self, agent_id: str = "local") -> Assignment | None:
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
            # Built from what has been issued, not what has finished, so two
            # concurrent hand-outs do not collapse onto the same state.
            state = self._state()
            policy = self.policy_for(agent_id)
            # Only offer this agent what its own policy permits, then validate;
            # otherwise one restricted agent would stall the whole run.
            permitted = tuple(
                item for item in candidates if _permitted(policy, self.catalog, item, index)
            )
            deferred = self._scarce_for_others(agent_id, permitted)
            preferred = tuple(item for item in permitted if item not in deferred)
            if preferred and deferred:
                self._emit(
                    "ability.deferred",
                    {
                        "index": index,
                        "agent_id": agent_id,
                        "abilities": sorted(deferred),
                        "reason": "reserved for an agent with no alternative",
                    },
                )
                permitted = preferred
            if not permitted:
                self._emit(
                    "ability.withheld",
                    {
                        "index": index,
                        "agent_id": agent_id,
                        "candidates": list(candidates),
                        "reason": "no candidate satisfies this agent's policy",
                    },
                )
                return None
            ability_id = self.rl.choose(state, permitted)
            policy.validate(self.catalog, ability_id, index)
            self._used.add(ability_id)
            self._issued += 1
            self._pending[f"{agent_id}:{ability_id}"] = (state, ability_id)
            ability = self.catalog.get(ability_id)
            bindings = bind(ability, self.facts)
            self._emit(
                "ability.approved",
                {
                    "index": index,
                    "agent_id": agent_id,
                    "ability_id": ability.id,
                    "technique": ability.technique,
                    "policy": "agent" if agent_id in self.agent_policies else "lab",
                    "bindings": dict(bindings),
                },
            )
            return Assignment(ability_id, bindings)

    def record_result(self, result: ExecutionResult, agent_id: str = "local") -> None:
        """Score a result, update the policy, and replan for what is left."""
        with self._lock:
            key = f"{agent_id}:{result.ability_id}"
            state, ability_id = self._pending.pop(
                key,
                (self._state(), result.ability_id),
            )
            ability = self.catalog.get(ability_id)
            self._emit("ability.completed", {"agent_id": agent_id, **asdict(result)})
            self._observations = (
                *self._observations,
                f"{ability_id}:{result.status}:{result.return_code}",
            )
            discovered = [
                fact
                for fact in extract(self.catalog, ability, result.stdout)
                if self.facts.add(fact)
            ]
            if discovered:
                unlocked = sorted(
                    item
                    for item in self.catalog.ids()
                    if item not in self._used and self._available(item)
                    and self.catalog.get(item).requires
                )
                self._emit(
                    "facts.discovered",
                    {
                        "agent_id": agent_id,
                        "ability_id": ability_id,
                        "facts": [{"trait": f.trait, "value": f.value} for f in discovered],
                        "unlocked": unlocked,
                    },
                )
            breakdown = self.reward_model.score(
                result,
                self.policy_for(agent_id),
                ability,
                depth=self.catalog.depth(ability_id),
            )
            self._emit(
                "reward.scored",
                {"agent_id": agent_id, "ability_id": ability_id, **breakdown.as_details()},
            )
            if result.status not in SUCCESS_STATUSES:
                self._outcome = DEGRADED
            next_state = self._state()
            self.rl.update(
                state,
                ability_id,
                breakdown.total,
                next_state,
                tuple(
                    item
                    for item in self.catalog.ids()
                    if item not in self._used and self._available(item)
                ),
            )
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
