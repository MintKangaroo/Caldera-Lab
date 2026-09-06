"""Measure a planner against the best order that was actually available.

A learning curve on its own says nothing: 56% of what? The reference has to be
the exact optimum, and it is cheap to compute here -- but only because reward
per ability happens to be order independent for this catalog, which is an
assumption this module checks rather than trusts.

Outputs come from a recorded run, so the measurement is of the real lab and
not of invented output.
"""

from __future__ import annotations

import functools
import random
from dataclasses import dataclass
from pathlib import Path

from .catalog import AbilityCatalog
from .coordinator import Coordinator
from .executor import ExecutionResult, FaultInjector
from .facts import extract
from .policy import LabPolicy
from .reward import RewardModel

__all__ = [
    "Bounds",
    "Concurrency",
    "concurrency",
    "DependencyNotObserved",
    "NotOrderIndependent",
    "TooManyAbilities",
    "bounds",
    "discounted",
    "evaluate",
    "load_outcomes",
    "order_spread",
    "under_faults",
]

GAMMA = 0.85
# 2^n subsets, so the exact search stops being cheap well before it stops
# being possible. Refuse rather than hang.
MAX_ABILITIES = 20


class TooManyAbilities(ValueError):
    """The exact search is exponential in the catalog size."""


class NotOrderIndependent(ValueError):
    """Per-ability reward depends on what ran before it, so the search is wrong.

    The dynamic program assumes an ability is worth the same wherever it
    appears. Information gain is normalised, so two abilities with identical
    output do not break it -- the same total simply moves between them. What
    breaks it is overlap of different sizes: if one ability prints two lines
    and another prints only the first of them, running the short one first
    leaves the long one half novel, and the run is worth more.
    """


class DependencyNotObserved(ValueError):
    """A declared dependency never actually resolved in the recorded run.

    The search decides what is available from the catalog: run a producer and
    its trait is known. A real run decides it from the output, which has to
    match the extraction pattern. When the two disagree the search reports a
    best order the lab could never take, so the recorded outputs have to show
    every declared trait actually being produced.
    """


@dataclass(frozen=True)
class Bounds:
    best: float
    best_order: tuple[str, ...]
    worst: float
    worst_order: tuple[str, ...]

    @property
    def headroom(self) -> float:
        return self.best - self.worst

    def position(self, value: float) -> float:
        """Where a measured return sits in the range, as a percentage."""
        return 100.0 * (value - self.worst) / self.headroom if self.headroom else 0.0


def load_outcomes(events: list[dict[str, object]]) -> dict[str, str]:
    """Recover each ability's recorded stdout from an audit log."""
    outcomes: dict[str, str] = {}
    for record in events:
        if record.get("event") != "ability.completed":
            continue
        details = record.get("details")
        if isinstance(details, dict) and isinstance(details.get("ability_id"), str):
            outcomes[details["ability_id"]] = str(details.get("stdout", ""))
    return outcomes


def discounted(rewards: list[float], gamma: float = GAMMA) -> float:
    return sum(gamma**step * reward for step, reward in enumerate(rewards))


class _Scorer:
    def __init__(
        self,
        catalog: AbilityCatalog,
        outcomes: dict[str, str],
        policy: LabPolicy | None = None,
    ) -> None:
        missing = sorted(set(catalog.ids()) - set(outcomes))
        if missing:
            raise ValueError(f"no recorded output for: {', '.join(missing)}")
        self.catalog = catalog
        self.outcomes = outcomes
        self.policy = policy or LabPolicy()

    def result(self, ability_id: str) -> ExecutionResult:
        return ExecutionResult(
            ability_id, "succeeded", self.outcomes[ability_id], "", 0, "replay", 0.0
        )

    def score(self, model: RewardModel, ability_id: str) -> float:
        return model.score(
            self.result(ability_id),
            self.policy,
            self.catalog.get(ability_id),
            depth=self.catalog.depth(ability_id),
        ).total

    @functools.cache  # noqa: B019 - lives as long as the scorer
    def alone(self, ability_id: str) -> float:
        """What the ability is worth to a run that has seen nothing else."""
        return self.score(RewardModel(), ability_id)

    def rollout(self, order: tuple[str, ...]) -> list[float]:
        model = RewardModel()
        return [self.score(model, ability_id) for ability_id in order]


class _Replay:
    """Hands back what the recorded run produced, so faults are the only variable."""

    def __init__(self, scorer: _Scorer) -> None:
        self.scorer = scorer

    def execute(self, ability: object, policy: LabPolicy) -> ExecutionResult:
        return self.scorer.result(ability.id)


def feasible_order(catalog: AbilityCatalog, rng: random.Random) -> tuple[str, ...]:
    """A random order that respects every precondition."""
    order: list[str] = []
    known: set[str] = set()
    while len(order) < len(catalog.ids()):
        available = [
            item
            for item in catalog.ids()
            if item not in order and set(catalog.get(item).requires) <= known
        ]
        if not available:
            break
        chosen = rng.choice(available)
        order.append(chosen)
        known.update(producer.trait for producer in catalog.get(chosen).produces)
    return tuple(order)


def order_spread(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    trials: int = 200,
    policy: LabPolicy | None = None,
) -> float:
    """Largest difference in total reward across random feasible full sweeps.

    Zero means the reward is a function of the set executed, which is what the
    exact search needs. It is also why ordering only matters through
    discounting.
    """
    scorer = _Scorer(catalog, outcomes, policy)
    rng = random.Random(17)
    totals = [sum(scorer.rollout(feasible_order(catalog, rng))) for _ in range(trials)]
    return max(totals) - min(totals) if totals else 0.0


def unproduced_traits(catalog: AbilityCatalog, outcomes: dict[str, str]) -> dict[str, list[str]]:
    """Traits an ability declares but whose recorded output does not yield."""
    gaps: dict[str, list[str]] = {}
    for ability in catalog.all():
        if not ability.produces:
            continue
        found = {fact.trait for fact in extract(catalog, ability, outcomes.get(ability.id, ""))}
        missing = sorted({p.trait for p in ability.produces} - found)
        if missing:
            gaps[ability.id] = missing
    return gaps


def bounds(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    gamma: float = GAMMA,
    policy: LabPolicy | None = None,
    check_trials: int = 200,
    tolerance: float = 1e-6,
) -> Bounds:
    """Best and worst discounted return over every feasible order."""
    if len(catalog.ids()) > MAX_ABILITIES:
        raise TooManyAbilities(
            f"exact search covers up to {MAX_ABILITIES} abilities, "
            f"catalog has {len(catalog.ids())}"
        )
    gaps = unproduced_traits(catalog, outcomes)
    if gaps:
        detail = "; ".join(f"{item}: {', '.join(traits)}" for item, traits in gaps.items())
        raise DependencyNotObserved(
            f"recorded output produces no value for {detail}, so the abilities "
            "depending on them were never actually reachable"
        )
    if check_trials:
        spread = order_spread(catalog, outcomes, check_trials, policy)
        if spread > tolerance:
            raise NotOrderIndependent(
                f"total reward varies by {spread:.6f} across orders; "
                "the exact search assumes it does not"
            )

    scorer = _Scorer(catalog, outcomes, policy)
    produces = {
        item: frozenset(p.trait for p in catalog.get(item).produces) for item in catalog.ids()
    }
    requires = {item: frozenset(catalog.get(item).requires) for item in catalog.ids()}

    @functools.cache
    def search(done: frozenset[str], pick_best: bool) -> tuple[float, tuple[str, ...]]:
        known: set[str] = set()
        for item in done:
            known |= produces[item]
        available = [item for item in catalog.ids() if item not in done and requires[item] <= known]
        if not available:
            return 0.0, ()
        choose = max if pick_best else min
        options = []
        for item in available:
            rest, order = search(done | {item}, pick_best)
            options.append((scorer.alone(item) + gamma * rest, (item, *order)))
        return choose(options, key=lambda option: option[0])

    best, best_order = search(frozenset(), True)
    worst, worst_order = search(frozenset(), False)
    return Bounds(best, best_order, worst, worst_order)


def evaluate(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    episodes: int = 0,
    state_mode: str | None = None,
    gamma: float = GAMMA,
    seed: int = 0,
    fault_rate: float = 0.0,
    fault_rates: dict[str, float] | None = None,
    max_attempts: int = 1,
    table: dict[tuple[str, str], float] | None = None,
) -> tuple[float, tuple[str, ...]]:
    """Train for `episodes`, then measure one greedy run over recorded output.

    With a fault rate the lab spoils that share of executions, which is the
    only way this sandbox meets failure: the same fixed reads of the same
    throwaway container otherwise succeed every time. Pass `table` to measure a
    policy that was trained somewhere else.
    """
    scorer = _Scorer(catalog, outcomes)
    limit = len(catalog.ids())
    if table is None:
        table = {}

    def episode(greedy: bool, policy_seed: int) -> tuple[float, tuple[str, ...]]:
        coordinator = Coordinator(
            catalog, planner_mode="rules", seed=policy_seed, max_steps=limit,
            state_mode=state_mode, policy=LabPolicy(max_attempts=max_attempts),
        )
        coordinator.rl.q = table
        if greedy:
            coordinator.rl.epsilon = 0.0
            _exploit_only(coordinator.rl)
        executor = FaultInjector(
            _Replay(scorer), fault_rate, seed=policy_seed, rates=fault_rates
        )
        coordinator.start()
        ran: list[str] = []
        while (assignment := coordinator.next_assignment()) is not None:
            coordinator.record_result(
                executor.execute(catalog.get(assignment.ability_id), LabPolicy())
            )
            ran.append(assignment.ability_id)
        rewards = [
            float(event.details["total"])
            for event in coordinator.events
            if event.event == "reward.scored"
        ]
        return discounted(rewards, gamma), tuple(ran)

    for index in range(episodes):
        episode(False, seed + index)
    return episode(True, seed)


def under_faults(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    table: dict[tuple[str, str], float],
    fault_rate: float = 0.0,
    trials: int = 200,
    state_mode: str | None = None,
    gamma: float = GAMMA,
    fault_rates: dict[str, float] | None = None,
    max_attempts: int = 1,
) -> float:
    """Mean discounted return of an already-trained policy across fault draws.

    Faults make the outcome of a run a distribution, so a single number needs
    an average -- and the exact search stops being the right reference, because
    the best order is no longer a property of the catalog alone.
    """
    total = 0.0
    for trial in range(trials):
        value, _ = evaluate(
            catalog, outcomes, episodes=0, state_mode=state_mode, gamma=gamma,
            seed=10_000 + trial, fault_rate=fault_rate, fault_rates=fault_rates,
            max_attempts=max_attempts, table=dict(table),
        )
        total += value
    return total / trials if trials else 0.0


@dataclass(frozen=True)
class Concurrency:
    """What concurrent dispatch does to the states a policy sees."""

    agents: int
    distinct_states: int
    lookups: int
    hits: int

    @property
    def transfer(self) -> float:
        """Share of lookups a sequentially trained table can answer."""
        return 100.0 * self.hits / self.lookups if self.lookups else 0.0


def _exploit_only(policy: object) -> None:
    """Make a greedy run exploit what was learned instead of exploring.

    An unmeasured pair is deliberately attractive during learning, so a run
    that just sets epsilon to zero still walks into actions nobody has tried.
    Measuring a learned policy means asking what it does among the actions it
    actually has values for.
    """
    table = policy.q

    def measured_only(state: str, action: str) -> float:
        return table.get((state, action), float("-inf"))

    policy.value = measured_only


def _dispatch(
    catalog: AbilityCatalog,
    scorer: _Scorer,
    agents: int,
    state_mode: str | None,
    table: dict[tuple[str, str], float] | None = None,
    greedy: bool = False,
    seed: int = 0,
) -> list[str]:
    """Run once, handing work to `agents` agents before any of them reports.

    Returns the state used at each hand-out. A burst is the case the state has
    to get right: nothing has completed, so a state built from finished work
    would be identical for every agent in it.
    """
    coordinator = Coordinator(
        catalog, planner_mode="rules", seed=seed,
        max_steps=len(catalog.ids()), state_mode=state_mode,
    )
    if table is not None:
        coordinator.rl.q = table
    if greedy:
        coordinator.rl.epsilon = 0.0
        _exploit_only(coordinator.rl)
    seen: list[str] = []
    original = coordinator.rl.choose

    def spy(state: str, candidates: tuple[str, ...]) -> str:
        seen.append(state)
        return original(state, candidates)

    coordinator.rl.choose = spy
    coordinator.start()
    done = False
    while not done:
        batch: list[tuple[str, str]] = []
        for index in range(agents):
            assignment = coordinator.next_assignment(f"agent-{index + 1}")
            if assignment is None:
                done = True
                break
            batch.append((f"agent-{index + 1}", assignment.ability_id))
        for agent_id, ability_id in batch:
            coordinator.record_result(scorer.result(ability_id), agent_id=agent_id)
    return seen


def concurrency(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    agents: int,
    episodes: int = 0,
    state_mode: str | None = None,
    seed: int = 0,
) -> Concurrency:
    """Distinct states under a burst, and how much sequential training carries.

    Training is sequential; the measured run is concurrent. A key a burst asks
    for that sequential training never wrote is learning the two modes cannot
    share.
    """
    scorer = _Scorer(catalog, outcomes)
    table: dict[tuple[str, str], float] = {}
    for index in range(episodes):
        _dispatch(catalog, scorer, 1, state_mode, table, seed=seed + index)
    learned = {state for state, _ in table}
    seen = _dispatch(catalog, scorer, agents, state_mode, dict(table), greedy=True, seed=seed)
    hits = sum(1 for state in seen if state in learned) if learned else 0
    return Concurrency(agents, len(set(seen)), len(seen), hits)


def render_concurrency(rows: list[Concurrency], trained: bool) -> str:
    lines = [f"{'agents':>7}  {'distinct states':>15}"]
    if trained:
        lines[0] += f"  {'transfer':>9}"
    for row in rows:
        line = f"{row.agents:>7}  {row.distinct_states:>15}"
        if trained:
            line += f"  {row.transfer:>8.1f}%"
        lines.append(line)
    return "\n".join(lines)


def render(bounds_: Bounds, measured: dict[int, tuple[float, tuple[str, ...]]]) -> str:
    lines = [
        f"best feasible order   {bounds_.best:.4f}",
        f"worst feasible order  {bounds_.worst:.4f}",
        f"headroom              {bounds_.headroom:.4f}",
        "",
        "best order",
    ]
    lines.extend(f"  {item}" for item in bounds_.best_order)
    if measured:
        lines.append("")
        lines.append(f"{'episodes':>9}  {'return':>8}  {'of headroom':>12}")
        for episodes in sorted(measured):
            value, _ = measured[episodes]
            lines.append(
                f"{episodes:>9}  {value:>8.4f}  {bounds_.position(value):>11.1f}%"
            )
    return "\n".join(lines)


def outcomes_from_log(path: Path) -> dict[str, str]:
    from .report import load_events

    return load_outcomes(load_events(path))
