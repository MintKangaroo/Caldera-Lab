from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

from .executor import ExecutionResult
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
    def facts(stdout: str) -> list[str]:
        """Normalise output into comparable facts, one per non-blank line."""
        return [" ".join(line.split()) for line in stdout.splitlines() if line.strip()]

    def score(self, result: ExecutionResult, policy: LabPolicy) -> RewardBreakdown:
        succeeded = result.status in {"succeeded", "planned"}
        outcome = self.success_reward if succeeded else self.failure_penalty

        novel = 0
        known = 0
        if succeeded:
            for fact in self.facts(result.stdout):
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
        )
