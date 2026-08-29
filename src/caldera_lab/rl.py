from __future__ import annotations

import json
import random
from pathlib import Path

from .catalog import AbilityCatalog

Q_TABLE_VERSION = 1


class QPolicy:
    """Small tabular policy used to rank safe abilities; it never creates commands."""

    def __init__(
        self,
        catalog: AbilityCatalog,
        seed: int = 7,
        epsilon: float = 0.15,
        alpha: float = 0.2,
        gamma: float = 0.85,
    ) -> None:
        self.catalog = catalog
        self.random = random.Random(seed)
        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        self.q: dict[tuple[str, str], float] = {}

    def state(self, observations: tuple[str, ...]) -> str:
        """Abstract observations into a state the table can actually revisit.

        Hashing the raw observation history made every state unique, so no
        (state, action) entry was ever read back and learning was inert. The
        state is instead which abilities have completed plus how the last one
        ended, which bounds the space at 2^len(catalog) * 3.
        """
        completed: set[str] = set()
        last = "none"
        for observation in observations:
            ability_id, _, remainder = observation.partition(":")
            status, _, _ = remainder.partition(":")
            if ability_id in self.catalog.ids():
                completed.add(ability_id)
            last = status or "none"
        mask = "".join("1" if item in completed else "0" for item in self.catalog.ids())
        return f"{mask}|{last}"

    def choose(self, state: str, candidates: tuple[str, ...]) -> str:
        if not candidates:
            raise ValueError("No candidate abilities")
        if self.random.random() < self.epsilon:
            return self.random.choice(candidates)
        best = max(self.q.get((state, item), 0.0) for item in candidates)
        # Ties are broken by catalog order so a run is reproducible for a given seed.
        return next(item for item in candidates if self.q.get((state, item), 0.0) == best)

    def update(self, state: str, action: str, reward: float, next_state: str) -> None:
        future = max(
            (self.q.get((next_state, item), 0.0) for item in self.catalog.ids()),
            default=0.0,
        )
        old = self.q.get((state, action), 0.0)
        self.q[(state, action)] = old + self.alpha * (reward + self.gamma * future - old)

    def fingerprint(self) -> str:
        """Ties a saved table to the catalog it was learned against."""
        return "|".join(self.catalog.ids())

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": Q_TABLE_VERSION,
            "catalog": self.fingerprint(),
            "entries": [
                {"state": state, "action": action, "value": value}
                for (state, action), value in sorted(self.q.items())
            ],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def load(self, path: Path) -> bool:
        """Load a saved table. Returns False when it is absent or does not apply."""
        if not path.exists():
            return False
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("version") != Q_TABLE_VERSION:
            return False
        # A changed catalog changes what the state mask means, so stale values
        # would be silently misapplied to different abilities.
        if payload.get("catalog") != self.fingerprint():
            return False
        entries = payload.get("entries")
        if not isinstance(entries, list):
            return False
        table: dict[tuple[str, str], float] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                return False
            state, action, value = entry.get("state"), entry.get("action"), entry.get("value")
            if not isinstance(state, str) or action not in self.catalog.ids():
                return False
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
            table[(state, action)] = float(value)
        self.q = table
        return True
