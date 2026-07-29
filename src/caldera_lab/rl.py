from __future__ import annotations

import hashlib
import random

from .catalog import AbilityCatalog


class QPolicy:
    """Small tabular policy used to rank safe abilities; it never creates commands."""

    def __init__(self, catalog: AbilityCatalog, seed: int = 7, epsilon: float = 0.15) -> None:
        self.catalog = catalog
        self.random = random.Random(seed)
        self.epsilon = epsilon
        self.q: dict[tuple[str, str], float] = {}

    def choose(self, state: str, candidates: tuple[str, ...]) -> str:
        if not candidates:
            raise ValueError("No candidate abilities")
        if self.random.random() < self.epsilon:
            return self.random.choice(candidates)
        return max(candidates, key=lambda item: self.q.get((state, item), 0.0))

    def update(self, state: str, action: str, reward: float, next_state: str) -> None:
        future = max(
            (self.q.get((next_state, item), 0.0) for item in self.catalog.ids()),
            default=0.0,
        )
        old = self.q.get((state, action), 0.0)
        self.q[(state, action)] = old + 0.2 * (reward + 0.85 * future - old)

    @staticmethod
    def state(observations: tuple[str, ...]) -> str:
        return hashlib.sha256("\n".join(observations[-8:]).encode()).hexdigest()[:16]
