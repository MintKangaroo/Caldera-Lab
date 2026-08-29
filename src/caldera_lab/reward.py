from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from functools import lru_cache

from .catalog import Ability
from .executor import SUCCESS_STATUSES, ExecutionResult
from .policy import LabPolicy


@dataclass(frozen=True)
class RewardBreakdown:
    """Every term that produced a reward, so an audit can explain a choice."""

    total: float
    outcome: float
    information_gain: float
    cost: float
    novel_facts: int
    known_facts: int
    normalized: bool = False

    def as_details(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items()}


class RewardModel:
    """Scores an execution by what it revealed, not merely by exit status.

    A run whose abilities all exit 0 gives a constant signal under a
    status-only reward, so the Q values end up encoding nothing but the order
    the abilities happened to run in. Novelty is tracked per episode: facts are
    forgotten between runs, because a lab that had already seen every fact
    forever would be driven toward doing nothing at all.
    """

    def __init__(
        self,
        success_reward: float = 0.25,
        failure_penalty: float = -1.0,
        information_weight: float = 1.0,
        cost_weight: float = 0.25,
    ) -> None:
        self.success_reward = success_reward
        self.failure_penalty = failure_penalty
        self.information_weight = information_weight
        self.cost_weight = cost_weight
        self._seen: set[str] = set()

    def reset(self) -> None:
        self._seen.clear()

    @staticmethod
    def facts(stdout: str, volatile_patterns: tuple[str, ...] = ()) -> list[str]:
        """Normalise output into comparable facts, one per non-blank line.

        Whitespace is collapsed, then any pattern the ability declares volatile
        is masked, so output that merely changes between runs (a container
        hostname, a PID, a timestamp) stops looking like a new discovery.
        """
        compiled = _compile(volatile_patterns)
        collected: list[str] = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            fact = " ".join(line.split())
            for expression in compiled:
                fact = expression.sub("<volatile>", fact)
            collected.append(fact)
        return collected

    def score(
        self,
        result: ExecutionResult,
        policy: LabPolicy,
        ability: Ability | None = None,
    ) -> RewardBreakdown:
        succeeded = result.status in SUCCESS_STATUSES
        outcome = self.success_reward if succeeded else self.failure_penalty

        patterns = ability.volatile_patterns if ability else ()
        novel = 0
        known = 0
        if succeeded:
            for fact in self.facts(result.stdout, patterns):
                digest = hashlib.sha256(fact.encode("utf-8")).hexdigest()
                if digest in self._seen:
                    known += 1
                else:
                    self._seen.add(digest)
                    novel += 1
        observed = novel + known
        gain = self.information_weight * (novel / observed) if observed else 0.0

        budget = max(policy.timeout_seconds, 1)
        cost = self.cost_weight * min(1.0, max(0.0, result.duration_seconds) / budget)

        return RewardBreakdown(
            total=round(outcome + gain - cost, 6),
            outcome=round(outcome, 6),
            information_gain=round(gain, 6),
            cost=round(cost, 6),
            novel_facts=novel,
            known_facts=known,
            normalized=bool(patterns),
        )


@lru_cache(maxsize=128)
def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)
