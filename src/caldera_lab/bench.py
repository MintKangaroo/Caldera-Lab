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
import itertools
import random
from dataclasses import dataclass
from pathlib import Path

from .catalog import Ability, AbilityCatalog
from .coordinator import Coordinator
from .executor import ExecutionResult, FaultInjector
from .facts import extract
from .policy import LabPolicy
from .reward import RewardModel
from .rl import DEGRADED

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
    "LatentRiskBounds",
    "latent_risk_bounds",
    "MultiRiskBounds",
    "multi_risk_bounds",
    "NonstationaryRisk",
    "nonstationary_risk",
    "PlannerComparison",
    "planner_comparison",
    "ProbeValue",
    "probe_value",
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
class PlannerComparison:
    """What learning the order buys over the rules planner's fixed one.

    The rules planner proposes the catalog order and the model-backed planners
    only reorder ability ids that are re-validated locally -- and the Claude
    planner refuses this task outright and falls back to rules. So the contest
    is not LLM-vs-RL; it is the fixed catalog order against a policy that learns
    the order. This holds both lines: `rules` is the catalog order, `rl` the
    trained policy, both graded the same way and averaged over fault draws.
    """

    rules: float
    """The catalog order the rules planner would run."""
    rl: float
    """The trained tabular policy."""
    worst: float | None
    """Worst feasible order -- only defined for a clean run (no faults)."""
    best: float | None
    """Best feasible order (the DP optimum) -- clean runs only."""

    @property
    def rl_gain(self) -> float:
        """How much return the learned order adds over the catalog order."""
        return self.rl - self.rules

    @property
    def rules_position(self) -> float:
        """Where the catalog order sits in the clean feasible range, as a percent."""
        if self.worst is None or self.best is None or self.best == self.worst:
            return 0.0
        return 100.0 * (self.rules - self.worst) / (self.best - self.worst)


def planner_comparison(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    episodes: int = 12000,
    trials: int = 400,
    fault_rates: dict[str, float] | None = None,
    max_attempts: int = 1,
    gamma: float = GAMMA,
    state_mode: str | None = None,
) -> PlannerComparison:
    """Compare the rules planner's catalog order against the learned policy.

    Both are graded the same way -- averaged discounted return over `trials`
    fault draws (a single draw when there are no faults). With `fault_rates` the
    DP bounds no longer hold, so `worst`/`best` are reported only for a clean
    run. The rules line is the fixed catalog order; the RL line is trained for
    `episodes` under the same conditions and then graded greedily.
    """
    scorer = _Scorer(catalog, outcomes)
    order = catalog.ids()
    faults = fault_rates or {}
    rules = sum(
        _forced_order(catalog, scorer, order, 20_000 + t, faults, gamma)
        for t in range(trials)
    ) / trials
    table: dict[tuple[str, str], float] = {}
    evaluate(
        catalog, outcomes, episodes=episodes, state_mode=state_mode, gamma=gamma,
        fault_rates=faults, max_attempts=max_attempts, table=table,
    )
    rl = under_faults(
        catalog, outcomes, table, trials=trials, state_mode=state_mode, gamma=gamma,
        fault_rates=faults, max_attempts=max_attempts,
    )
    if fault_rates:
        return PlannerComparison(rules, rl, None, None)
    limits = bounds(catalog, outcomes, gamma=gamma)
    return PlannerComparison(rules, rl, limits.worst, limits.best)


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


@dataclass(frozen=True)
class LatentRiskBounds:
    """Where a policy lands when the risk changes every episode and is hidden.

    A rate the operator fixes is learned across episodes without ever entering
    the state -- the Q value of a risky chain is discounted by its failures on
    its own. A rate drawn fresh each episode is different: acting well needs
    this run's rate, whose only evidence is failures seen so far, and the
    state carries no per-ability failure history to hold that. These bounds say
    how much that costs.
    """

    no_information: float
    """Best single order, same every episode -- cannot use within-run evidence."""
    oracle: float
    """Best order per episode, told the rate -- the fully-informed ceiling."""
    measured: float
    """The trained tabular policy."""

    @property
    def headroom(self) -> float:
        return self.oracle - self.no_information

    @property
    def position(self) -> float:
        """Where the policy sits between no-information and oracle, as a percent.

        Below zero means the policy does worse than committing to one order:
        averaging the two regimes into one Q value costs more than it buys.
        """
        return (
            100.0 * (self.measured - self.no_information) / self.headroom
            if self.headroom
            else 0.0
        )


def _forced_order(
    catalog: AbilityCatalog,
    scorer: _Scorer,
    order: tuple[str, ...],
    seed: int,
    rates: dict[str, float],
    gamma: float,
) -> float:
    rank = {ability_id: index for index, ability_id in enumerate(order)}
    coordinator = Coordinator(catalog, planner_mode="rules", seed=seed, max_steps=len(order))
    coordinator.rl.choose = lambda state, candidates: min(candidates, key=lambda c: rank[c])
    executor = FaultInjector(_Replay(scorer), 0.0, seed=seed, rates=rates)
    coordinator.start()
    while (assignment := coordinator.next_assignment()) is not None:
        coordinator.record_result(
            executor.execute(catalog.get(assignment.ability_id), LabPolicy())
        )
    rewards = [
        float(event.details["total"])
        for event in coordinator.events
        if event.event == "reward.scored"
    ]
    return discounted(rewards, gamma)


def latent_risk_bounds(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    risky_ability: str,
    rates: tuple[float, ...],
    episodes: int = 12000,
    trials: int = 400,
    gamma: float = GAMMA,
    state_mode: str | None = None,
    canary: str | None = None,
) -> LatentRiskBounds:
    """Bound the per-episode latent-risk problem for one risky ability.

    Each episode draws one of `rates` for `risky_ability`, uniformly. The
    no-information and oracle lines come from forcing the two orders that
    matter -- the chain first, or the risky ability's dependents deferred to
    the end -- at each rate. The policy is trained and measured on the same mix.

    Without a canary the only evidence of the drawn rate is the risky ability's
    own failure, which is also the costly commitment: by the time it is
    observed the decision is made and its dependents are gone, so the
    information arrives too late to act on. Pass `canary` -- a cheap ability
    that fails at the same latent rate but has nothing depending on it -- and
    the evidence is available before the commitment. The `degraded` bit already
    in the state carries it; no larger state is needed, and enlarging it to
    chase this instead slows convergence for nothing.
    """
    for name in (risky_ability, canary):
        if name is not None and name not in catalog.ids():
            raise ValueError(f"unknown ability: {name}")
    scorer = _Scorer(catalog, outcomes)

    def rates_for(rate: float) -> dict[str, float]:
        drawn = {risky_ability: rate}
        if canary is not None:
            drawn[canary] = rate
        return drawn
    best = bounds(catalog, outcomes, gamma=gamma).best_order
    dependents = [
        item
        for item in catalog.ids()
        if item == risky_ability
        or _reaches(catalog, item, risky_ability)
    ]
    deferred = tuple(
        [item for item in best if item not in dependents]
        + [item for item in best if item in dependents]
    )

    def per_rate(order: tuple[str, ...], rate: float) -> float:
        return sum(
            _forced_order(catalog, scorer, order, 20_000 + t, rates_for(rate), gamma)
            for t in range(trials)
        ) / trials

    by_order = {
        "chain_first": {rate: per_rate(best, rate) for rate in rates},
        "deferred": {rate: per_rate(deferred, rate) for rate in rates},
    }
    no_information = max(
        sum(values.values()) / len(rates) for values in by_order.values()
    )
    oracle = sum(
        max(by_order[order][rate] for order in by_order) for rate in rates
    ) / len(rates)

    def play(
        table: dict[tuple[str, str], float], seed: int, rate: float, greedy: bool
    ) -> float:
        coordinator = Coordinator(
            catalog, planner_mode="rules", seed=seed, max_steps=len(catalog.ids()),
            state_mode=state_mode,
        )
        coordinator.rl.q = table
        if greedy:
            coordinator.rl.epsilon = 0.0
            _exploit_only(coordinator.rl)
        executor = FaultInjector(_Replay(scorer), 0.0, seed=seed, rates=rates_for(rate))
        coordinator.start()
        while (assignment := coordinator.next_assignment()) is not None:
            coordinator.record_result(
                executor.execute(catalog.get(assignment.ability_id), LabPolicy())
            )
        rewards = [
            float(event.details["total"])
            for event in coordinator.events
            if event.event == "reward.scored"
        ]
        return discounted(rewards, gamma)

    table: dict[tuple[str, str], float] = {}
    picker = random.Random(1)
    for index in range(episodes):
        play(table, index, rates[picker.randrange(len(rates))], greedy=False)
    picker = random.Random(2)
    measured = sum(
        play(dict(table), 30_000 + t, rates[picker.randrange(len(rates))], greedy=True)
        for t in range(trials)
    ) / trials
    return LatentRiskBounds(no_information, oracle, measured)


@dataclass(frozen=True)
class MultiRiskBounds:
    """What one degraded bit can do when several latent risks fire independently.

    One risk needed one bit: the bit was 0 in the safe world and 1 in the bad
    one, so it named the world exactly. With several independent risks the bit
    still flips on any failure, so it separates "all safe" from "something
    failed" but cannot say *which* risk fired -- and the right order differs by
    which one did. These bounds say how much of the informed ceiling a single
    bit can still reach.
    """

    no_information: float
    """Best single order, same every episode."""
    oracle: float
    """Best order per world, told which risks fired -- the informed ceiling."""
    one_bit: float
    """The trained policy, whose only failure evidence is one shared bit."""
    per_risk: float
    """A policy with a failure bit per watched risk, so it can tell them apart."""
    worlds: int
    """How many distinct risk worlds the mix draws from."""

    @property
    def headroom(self) -> float:
        return self.oracle - self.no_information

    def _position(self, value: float) -> float:
        return 100.0 * (value - self.no_information) / self.headroom if self.headroom else 0.0

    @property
    def position(self) -> float:
        """Where the one-bit policy sits between no-information and oracle."""
        return self._position(self.one_bit)

    @property
    def per_risk_position(self) -> float:
        """Where the per-risk-bit policy sits -- how much naming the culprit recovers."""
        return self._position(self.per_risk)


def multi_risk_bounds(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    risks: tuple[str, ...],
    rates: tuple[float, ...] = (0.0, 0.9),
    canaries: tuple[str | None, ...] | None = None,
    correlated: bool = False,
    episodes: int = 12000,
    trials: int = 400,
    gamma: float = GAMMA,
    state_mode: str | None = None,
) -> MultiRiskBounds:
    """Bound the per-episode problem when several risks are drawn each episode.

    Each risk in `risks` draws a rate from `rates` every episode; a canary
    beside it fails at the same drawn rate. With `correlated` the risks share
    one draw (so the worlds collapse to `rates`), otherwise they are drawn
    independently (so there are ``len(rates) ** len(risks)`` worlds). The
    reference orders defer each subset of the risky chains; the oracle picks the
    best order per world, the no-information line the best single order over the
    mix. The policy trains and is measured on the same mix, seeing only the one
    shared degraded bit -- the point of the comparison.
    """
    canaries = canaries or tuple(None for _ in risks)
    if len(canaries) != len(risks):
        raise ValueError("canaries must match risks")
    for name in (*risks, *(c for c in canaries if c is not None)):
        if name not in catalog.ids():
            raise ValueError(f"unknown ability: {name}")
    scorer = _Scorer(catalog, outcomes)
    best = bounds(catalog, outcomes, gamma=gamma).best_order

    dependents = {
        risk: {item for item in catalog.ids() if item == risk or _reaches(catalog, item, risk)}
        for risk in risks
    }

    def order_deferring(subset: tuple[int, ...]) -> tuple[str, ...]:
        deferred_ids: set[str] = set()
        for index in subset:
            deferred_ids |= dependents[risks[index]]
        return tuple(
            [item for item in best if item not in deferred_ids]
            + [item for item in best if item in deferred_ids]
        )

    subsets = [
        subset
        for size in range(len(risks) + 1)
        for subset in itertools.combinations(range(len(risks)), size)
    ]
    candidate_orders = {subset: order_deferring(subset) for subset in subsets}

    if correlated:
        worlds = [tuple(rate for _ in risks) for rate in rates]
    else:
        worlds = list(itertools.product(rates, repeat=len(risks)))
    world_prob = 1.0 / len(worlds)

    def rates_for(world: tuple[float, ...]) -> dict[str, float]:
        drawn: dict[str, float] = {}
        for index, risk in enumerate(risks):
            drawn[risk] = world[index]
            if canaries[index] is not None:
                drawn[canaries[index]] = world[index]
        return drawn

    @functools.cache
    def value(order: tuple[str, ...], world: tuple[float, ...]) -> float:
        return sum(
            _forced_order(catalog, scorer, order, 20_000 + t, rates_for(world), gamma)
            for t in range(trials)
        ) / trials

    oracle = sum(
        world_prob * max(value(order, world) for order in candidate_orders.values())
        for world in worlds
    )
    no_information = max(
        sum(world_prob * value(order, world) for world in worlds)
        for order in candidate_orders.values()
    )

    def draw_world(rng: random.Random) -> tuple[float, ...]:
        if correlated:
            rate = rng.choice(rates)
            return tuple(rate for _ in risks)
        return tuple(rng.choice(rates) for _ in risks)

    def play(
        table: dict[tuple[str, str], float], seed: int, world: tuple[float, ...],
        greedy: bool, watch: tuple[str, ...] = (),
    ) -> float:
        coordinator = Coordinator(
            catalog, planner_mode="rules", seed=seed, max_steps=len(catalog.ids()),
            state_mode=state_mode, watch=watch,
        )
        coordinator.rl.q = table
        if greedy:
            coordinator.rl.epsilon = 0.0
            _exploit_only(coordinator.rl)
        executor = FaultInjector(_Replay(scorer), 0.0, seed=seed, rates=rates_for(world))
        coordinator.start()
        while (assignment := coordinator.next_assignment()) is not None:
            coordinator.record_result(
                executor.execute(catalog.get(assignment.ability_id), LabPolicy())
            )
        rewards = [
            float(event.details["total"])
            for event in coordinator.events
            if event.event == "reward.scored"
        ]
        return discounted(rewards, gamma)

    def trained_return(watch: tuple[str, ...]) -> float:
        table: dict[tuple[str, str], float] = {}
        trainer = random.Random(1)
        for index in range(episodes):
            play(table, index, draw_world(trainer), greedy=False, watch=watch)
        grader = random.Random(2)
        return sum(
            play(dict(table), 30_000 + t, draw_world(grader), greedy=True, watch=watch)
            for t in range(trials)
        ) / trials

    # Watch the earliest observable signal of each risk: its canary if it has
    # one (run before the risky chain is committed), else the risky ability.
    watched = tuple(
        canaries[index] if canaries[index] is not None else risk
        for index, risk in enumerate(risks)
    )
    one_bit = trained_return(())
    per_risk = trained_return(watched)
    return MultiRiskBounds(no_information, oracle, one_bit, per_risk, len(worlds))


@dataclass(frozen=True)
class NonstationaryRisk:
    """Whether within-episode adaptivity survives a shift in the risk mix.

    Each episode draws a low or a high rate; the probability of the high one
    shifts partway through, and the optimal order flips with the drawn rate.
    The mix therefore decides which single order a *prior-committed* policy
    should pick -- and when the mix crosses the flip point, the order it
    committed to before is now the wrong one.

    Two learners are trained on the before mix and graded on the after mix,
    against learners trained on the after mix. The RL policy is free to reorder
    within an episode (it reads the risky ability's own outcome, the canary it
    already carries); the commit policy is the best single order for its mix.
    """

    rl_stale: float
    """RL trained on the before mix, graded on the after mix."""
    rl_adapted: float
    """RL trained on the after mix, graded on the after mix."""
    commit_stale: float
    """Best single order for the before mix, on the after mix."""
    commit_adapted: float
    """Best single order for the after mix, on the after mix."""

    @property
    def rl_relearning(self) -> float:
        """What re-training the RL policy on the new mix recovers. Near zero means
        the shift cost it nothing -- it was already adapting per episode."""
        return self.rl_adapted - self.rl_stale

    @property
    def commit_relearning(self) -> float:
        """What re-choosing the committed order recovers -- the cost of staleness
        for a policy that cannot adapt within an episode."""
        return self.commit_adapted - self.commit_stale


def nonstationary_risk(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    risky_ability: str,
    before_high: float,
    after_high: float,
    low_rate: float = 0.0,
    high_rate: float = 0.9,
    episodes: int = 12000,
    trials: int = 400,
    gamma: float = GAMMA,
    state_mode: str | None = None,
) -> NonstationaryRisk:
    """Measure whether a converged policy is robust to a shift in the risk mix.

    Every episode draws `high_rate` with some probability, else `low_rate`; the
    optimal order flips with the drawn rate (chain-first when low, the risky
    chain deferred when high). The mix decides which single order a
    prior-committed policy should pick. This trains an RL policy and picks a
    best committed order on each of `before_high` and `after_high`, then grades
    both on the after mix: the before-trained ones are stale, and the gap to the
    after-trained ones is what re-learning recovers. The RL policy can reorder
    within an episode on the risky ability's own failure, so it need not commit
    to the mix; the comparison is how much that spares it when the mix shifts.
    """
    if risky_ability not in catalog.ids():
        raise ValueError(f"unknown ability: {risky_ability}")
    scorer = _Scorer(catalog, outcomes)
    best = bounds(catalog, outcomes, gamma=gamma).best_order
    dependents = [
        item
        for item in catalog.ids()
        if item == risky_ability or _reaches(catalog, item, risky_ability)
    ]
    deferred = tuple(
        [item for item in best if item not in dependents]
        + [item for item in best if item in dependents]
    )

    def rates_for(rate: float) -> dict[str, float]:
        return {risky_ability: rate}

    def play(
        table: dict[tuple[str, str], float], seed: int, rate: float, greedy: bool
    ) -> float:
        coordinator = Coordinator(
            catalog, planner_mode="rules", seed=seed, max_steps=len(catalog.ids()),
            state_mode=state_mode,
        )
        coordinator.rl.q = table
        if greedy:
            coordinator.rl.epsilon = 0.0
            _exploit_only(coordinator.rl)
        executor = FaultInjector(_Replay(scorer), 0.0, seed=seed, rates=rates_for(rate))
        coordinator.start()
        while (assignment := coordinator.next_assignment()) is not None:
            coordinator.record_result(
                executor.execute(catalog.get(assignment.ability_id), LabPolicy())
            )
        rewards = [
            float(event.details["total"])
            for event in coordinator.events
            if event.event == "reward.scored"
        ]
        return discounted(rewards, gamma)

    def rate_of(high: float, picker: random.Random) -> float:
        return high_rate if picker.random() < high else low_rate

    @functools.cache
    def forced_on(order: tuple[str, ...], rate: float) -> float:
        return sum(
            _forced_order(catalog, scorer, order, 20_000 + t, rates_for(rate), gamma)
            for t in range(trials)
        ) / trials

    def commit_on(order: tuple[str, ...], high: float) -> float:
        return high * forced_on(order, high_rate) + (1 - high) * forced_on(order, low_rate)

    def best_commit(high: float) -> tuple[str, ...]:
        return max((best, deferred), key=lambda order: commit_on(order, high))

    def rl_on(train_high: float, grade_high: float) -> float:
        table: dict[tuple[str, str], float] = {}
        trainer = random.Random(1)
        for index in range(episodes):
            play(table, index, rate_of(train_high, trainer), greedy=False)
        grader = random.Random(2)
        return sum(
            play(dict(table), 30_000 + trial, rate_of(grade_high, grader), greedy=True)
            for trial in range(trials)
        ) / trials

    return NonstationaryRisk(
        rl_stale=rl_on(before_high, after_high),
        rl_adapted=rl_on(after_high, after_high),
        commit_stale=commit_on(best_commit(before_high), after_high),
        commit_adapted=commit_on(best_commit(after_high), after_high),
    )


PROBE_ID = "observe-latent-canary"


def _with_probe(
    catalog: AbilityCatalog, outcomes: dict[str, str], probe_id: str
) -> tuple[AbilityCatalog, dict[str, str]]:
    """Append a pure probe to the catalog: a study construct, not a real ability.

    The probe reads nothing (empty output, so zero information gain) and unlocks
    nothing (no `produces`, so nothing depends on it and it depends on nothing).
    Its only content is that it can be made to fail at the latent rate. That
    isolates the question this experiment asks -- whether observing the risk is
    worth a step -- from the ability's own value: a real recon read is run for
    what it discovers regardless of the risk it also reveals, so it could never
    show a policy *declining* to observe. This never enters `catalog/abilities.json`
    and is never executed; it exists only inside the replay.
    """
    if probe_id in catalog.ids():
        raise ValueError(f"probe id collides with a real ability: {probe_id}")
    probe = Ability(
        id=probe_id,
        name="Latent-risk canary",
        tactic="reconnaissance",
        technique="T0000",
        command=("true",),
        description="Study-only probe: fails at the latent rate and reveals nothing.",
        risk="low",
    )
    augmented = AbilityCatalog((*catalog.all(), probe), catalog.traits())
    augmented._reject_unreachable()
    augmented._depth = augmented._measure_depth()
    return augmented, {**outcomes, probe_id: ""}


def _degraded(state: str) -> bool:
    """Read the failure bit the coordinator encodes at the tail of every state."""
    return state.rsplit("|", 1)[-1] == DEGRADED


def _commit_choose(order: tuple[str, ...], probe_id: str):  # noqa: ANN202
    """Follow a fixed order and never spend a step on the probe."""
    rank = {ability_id: index for index, ability_id in enumerate(order)}
    never = len(order) + 1

    def choose(state: str, candidates: tuple[str, ...]) -> str:
        return min(candidates, key=lambda c: never if c == probe_id else rank.get(c, never - 1))

    return choose


def _probe_first_choose(  # noqa: ANN202
    clean_order: tuple[str, ...], degraded_order: tuple[str, ...], probe_id: str
):
    """Probe first, then take the chain first if it looks safe, else defer it.

    The probe is a candidate only until it is issued, so preferring it whenever
    it appears runs it exactly once, at the start. After that the degraded bit
    already in the state says which order to follow for the rest.
    """
    clean_rank = {ability_id: index for index, ability_id in enumerate(clean_order)}
    degraded_rank = {ability_id: index for index, ability_id in enumerate(degraded_order)}
    last = max(len(clean_order), len(degraded_order)) + 1

    def choose(state: str, candidates: tuple[str, ...]) -> str:
        if probe_id in candidates:
            return probe_id
        rank = degraded_rank if _degraded(state) else clean_rank
        return min(candidates, key=lambda c: rank.get(c, last))

    return choose


def _budgeted_rollout(  # noqa: ANN202
    catalog: AbilityCatalog,
    scorer: _Scorer,
    choose,
    seed: int,
    rates: dict[str, float],
    gamma: float,
    budget: int,
    state_mode: str | None,
    greedy: bool = False,
    table: dict[tuple[str, str], float] | None = None,
) -> tuple[float, set[str]]:
    """Play one episode under a step budget; return its discounted value and what it issued."""
    coordinator = Coordinator(
        catalog,
        policy=LabPolicy(max_steps=budget),
        planner_mode="rules",
        seed=seed,
        state_mode=state_mode,
    )
    if table is not None:
        coordinator.rl.q = table
    if choose is not None:
        coordinator.rl.choose = choose
    elif greedy:
        coordinator.rl.epsilon = 0.0
        _exploit_only(coordinator.rl)
    executor = FaultInjector(_Replay(scorer), 0.0, seed=seed, rates=rates)
    coordinator.start()
    while (assignment := coordinator.next_assignment()) is not None:
        coordinator.record_result(
            executor.execute(catalog.get(assignment.ability_id), LabPolicy())
        )
    rewards = [
        float(event.details["total"])
        for event in coordinator.events
        if event.event == "reward.scored"
    ]
    issued = {
        str(event.details["ability_id"])
        for event in coordinator.events
        if event.event == "ability.approved"
    }
    return discounted(rewards, gamma), issued


@dataclass(frozen=True)
class ProbeValue:
    """Whether a policy should pay a step to observe a latent risk before acting.

    `commit` never probes and commits to the chain-first order; `probe` always
    spends the first step on the probe and then defers the risky chain when the
    probe failed. `best_fixed` is the better of those two blind strategies for
    this prior. `policy` is the trained tabular policy, and `probe_use` is the
    share of its evaluated episodes that chose to run the probe -- the decision
    itself, not just its payoff.
    """

    commit: float
    probe: float
    policy: float
    without_probe: float
    probe_use: float
    budget: int

    @property
    def best_fixed(self) -> float:
        return max(self.commit, self.probe)

    @property
    def probe_worth(self) -> float:
        """How much the probe strategy beats committing blind. Negative: not worth it."""
        return self.probe - self.commit

    @property
    def probe_gain(self) -> float:
        """What having the probe on offer buys the trained policy over not having it.

        Near zero means the policy gained nothing from a dedicated probe: the
        recon it runs anyway already revealed the risk in time.
        """
        return self.policy - self.without_probe


def probe_value(
    catalog: AbilityCatalog,
    outcomes: dict[str, str],
    risky_ability: str,
    rates: tuple[float, ...],
    weights: tuple[float, ...] | None = None,
    budget: int | None = None,
    probe_id: str = PROBE_ID,
    episodes: int = 12000,
    trials: int = 400,
    gamma: float = GAMMA,
    state_mode: str | None = None,
) -> ProbeValue:
    """Measure whether spending a step to observe a latent risk pays, and if the
    policy learns to make that call.

    Each episode draws one of `rates` for `risky_ability` (and for the probe,
    which fails with it), with probability `weights`. Under a step budget the
    probe competes with real discoveries, so running it is a genuine cost: a
    slot, plus the probe's own failure in a bad episode. Its benefit is the
    degraded bit arriving before the risky chain is committed, so the doomed
    chain can be deferred. The returned `ProbeValue` says what that trade is
    worth (`probe_gain`, `probe_worth`) and whether the trained policy takes it
    (`probe_use`).
    """
    if risky_ability not in catalog.ids():
        raise ValueError(f"unknown ability: {risky_ability}")
    weights = weights or tuple(1.0 for _ in rates)
    if len(weights) != len(rates):
        raise ValueError("weights must match rates")
    augmented, augmented_outcomes = _with_probe(catalog, outcomes, probe_id)
    if budget is None:
        budget = len(augmented.ids())
    scorer = _Scorer(augmented, augmented_outcomes)

    best = bounds(catalog, outcomes, gamma=gamma).best_order
    dependents = [
        item
        for item in catalog.ids()
        if item == risky_ability or _reaches(catalog, item, risky_ability)
    ]
    deferred = tuple(
        [item for item in best if item not in dependents]
        + [item for item in best if item in dependents]
    )

    def rates_for(rate: float) -> dict[str, float]:
        return {risky_ability: rate, probe_id: rate}

    def draw(rng: random.Random) -> float:
        return rng.choices(rates, weights=weights, k=1)[0]

    def forced_average(choose) -> float:  # noqa: ANN001
        rng = random.Random(101)
        total = 0.0
        for trial in range(trials):
            rate = draw(rng)
            value, _ = _budgeted_rollout(
                augmented, scorer, choose, 40_000 + trial, rates_for(rate),
                gamma, budget, state_mode,
            )
            total += value
        return total / trials

    commit = forced_average(_commit_choose(best, probe_id))
    probe = forced_average(_probe_first_choose(best, deferred, probe_id))

    table: dict[tuple[str, str], float] = {}
    trainer = random.Random(1)
    for index in range(episodes):
        _budgeted_rollout(
            augmented, scorer, None, index, rates_for(draw(trainer)),
            gamma, budget, state_mode, table=table,
        )
    grader = random.Random(2)
    returns = 0.0
    probed = 0
    for trial in range(trials):
        value, issued = _budgeted_rollout(
            augmented, scorer, None, 30_000 + trial, rates_for(draw(grader)),
            gamma, budget, state_mode, greedy=True, table=dict(table),
        )
        returns += value
        probed += int(probe_id in issued)

    # The same policy with no probe on offer, so the gain from having it is
    # measured against the recon the lab would run regardless.
    bare_scorer = _Scorer(catalog, outcomes)
    bare_budget = min(budget, len(catalog.ids()))
    bare_table: dict[tuple[str, str], float] = {}
    bare_trainer = random.Random(3)
    for index in range(episodes):
        _budgeted_rollout(
            catalog, bare_scorer, None, index, {risky_ability: draw(bare_trainer)},
            gamma, bare_budget, state_mode, table=bare_table,
        )
    bare_grader = random.Random(4)
    bare_returns = sum(
        _budgeted_rollout(
            catalog, bare_scorer, None, 30_000 + trial, {risky_ability: draw(bare_grader)},
            gamma, bare_budget, state_mode, greedy=True, table=dict(bare_table),
        )[0]
        for trial in range(trials)
    ) / trials

    return ProbeValue(commit, probe, returns / trials, bare_returns, probed / trials, budget)


def _reaches(catalog: AbilityCatalog, item: str, source: str) -> bool:
    """Whether `item` depends, directly or through the chain, on `source`."""
    produced_by = {
        producer.trait: ability.id
        for ability in catalog.all()
        for producer in ability.produces
    }
    seen: set[str] = set()
    frontier = list(catalog.get(item).requires)
    while frontier:
        trait = frontier.pop()
        producer = produced_by.get(trait)
        if producer is None or producer in seen:
            continue
        if producer == source:
            return True
        seen.add(producer)
        frontier.extend(catalog.get(producer).requires)
    return False


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
