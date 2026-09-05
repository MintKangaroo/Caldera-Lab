from __future__ import annotations

import json
import random
from pathlib import Path

from .catalog import AbilityCatalog
from .executor import SUCCESS_STATUSES

# 2: the outcome component became mode-invariant, so version 1 keys no longer
# mean what they used to and must not be reloaded.
Q_TABLE_VERSION = 2

CLEAN = "clean"
DEGRADED = "degraded"
OUTCOMES = frozenset({CLEAN, DEGRADED})


class QPolicy:
    """Small tabular policy used to rank safe abilities; it never creates commands."""

    def __init__(
        self,
        catalog: AbilityCatalog,
        seed: int = 7,
        epsilon: float = 0.15,
        alpha: float = 0.2,
        gamma: float = 0.85,
        optimism: float = 2.0,
    ) -> None:
        self.catalog = catalog
        self.random = random.Random(seed)
        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        # Every reward here is positive, so a table initialised at zero makes an
        # untried action look strictly worse than one already tried: whatever
        # the first tie-break picked would be confirmed forever and a better
        # order could never be found. An unseen pair is therefore worth more
        # than a measured one until it has been measured.
        self.optimism = optimism
        self.q: dict[tuple[str, str], float] = {}

    def state_from(self, committed: frozenset[str] | set[str], outcome: str) -> str:
        """Build a state from the abilities already committed and how the run is going.

        "Committed" means issued, not finished. Under concurrent dispatch a
        second agent is handed work before the first has reported, so a state
        built from completions alone would be identical for both and the two
        choices would fight over one table entry. Sequentially the two sets
        coincide, so this leaves single-agent behaviour unchanged.

        The outcome component is whether anything has failed yet rather than
        how the previous step ended. "The previous step" is not defined the
        same way in both modes: mid-burst a concurrent run has no completed
        step at all, so it asked for states a sequential run never visits and
        a table learned in one mode was dead weight in the other.
        """
        if outcome not in OUTCOMES:
            raise ValueError(f"Unknown outcome: {outcome!r}")
        mask = "".join("1" if item in committed else "0" for item in self.catalog.ids())
        return f"{mask}|{outcome}"

    def state(self, observations: tuple[str, ...]) -> str:
        """Abstract observations into a state the table can actually revisit.

        Hashing the raw observation history made every state unique, so no
        (state, action) entry was ever read back and learning was inert. The
        state is instead which abilities have completed plus whether anything
        has failed, which bounds the space at 2^len(catalog) * 2.
        """
        completed: set[str] = set()
        outcome = CLEAN
        for observation in observations:
            ability_id, _, remainder = observation.partition(":")
            status, _, _ = remainder.partition(":")
            if ability_id in self.catalog.ids():
                completed.add(ability_id)
            if status and status not in SUCCESS_STATUSES:
                outcome = DEGRADED
        return self.state_from(completed, outcome)

    def choose(self, state: str, candidates: tuple[str, ...]) -> str:
        if not candidates:
            raise ValueError("No candidate abilities")
        if self.random.random() < self.epsilon:
            return self.random.choice(candidates)
        best = max(self.value(state, item) for item in candidates)
        # Ties are broken by candidate order so a run is reproducible for a given seed.
        return next(item for item in candidates if self.value(state, item) == best)

    def value(self, state: str, action: str) -> float:
        return self.q.get((state, action), self.optimism)

    def update(
        self,
        state: str,
        action: str,
        reward: float,
        next_state: str,
        next_actions: tuple[str, ...] | None = None,
    ) -> None:
        """Back up the value of `state` from what is reachable after it.

        The future term is a max over the actions actually available next, not
        over the whole catalog. Over the whole catalog it is blind to an action
        that opened options: unlocking changes which actions exist, and a max
        that ignores availability values a state that unlocked three abilities
        exactly like one that unlocked none.
        """
        reachable = self.catalog.ids() if next_actions is None else next_actions
        future = max((self.value(next_state, item) for item in reachable), default=0.0)
        old = self.value(state, action)
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
