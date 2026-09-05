from __future__ import annotations

import re
from dataclasses import dataclass, replace
from functools import lru_cache

from .catalog import Ability, AbilityCatalog

__all__ = [
    "Fact",
    "FactRejected",
    "FactStore",
    "bind",
    "extract",
    "resolve",
]

PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


class FactRejected(ValueError):
    """A fact value does not match the shape its trait declares.

    Raised rather than skipped: a value that fails validation is the one case
    where substituting anyway would put attacker-influenced text into an argv.
    """


@dataclass(frozen=True)
class Fact:
    trait: str
    value: str


class FactStore:
    """Facts discovered during a run, in the order they were found.

    Insertion order matters: it is what makes the command a given ability runs
    reproducible for a given sequence of results.
    """

    def __init__(self) -> None:
        self._by_trait: dict[str, list[str]] = {}

    def add(self, fact: Fact) -> bool:
        """Record a fact. Returns whether it was new."""
        values = self._by_trait.setdefault(fact.trait, [])
        if fact.value in values:
            return False
        values.append(fact.value)
        return True

    def values(self, trait: str) -> tuple[str, ...]:
        return tuple(self._by_trait.get(trait, ()))

    def has(self, trait: str) -> bool:
        return bool(self._by_trait.get(trait))

    def traits(self) -> frozenset[str]:
        return frozenset(trait for trait, values in self._by_trait.items() if values)

    def satisfies(self, ability: Ability) -> bool:
        return all(self.has(trait) for trait in ability.requires)

    def as_dict(self) -> dict[str, list[str]]:
        return {trait: list(values) for trait, values in self._by_trait.items() if values}


@lru_cache(maxsize=256)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def extract(catalog: AbilityCatalog, ability: Ability, stdout: str) -> list[Fact]:
    """Pull declared facts out of an ability's output.

    A capture that does not match its trait's declared shape is dropped rather
    than stored, so a malformed line cannot widen what a trait may contain.
    """
    found: list[Fact] = []
    seen: set[tuple[str, str]] = set()
    for producer in ability.produces:
        shape = _compiled(catalog.trait_pattern(producer.trait))
        for match in _compiled(producer.pattern).finditer(stdout):
            value = match.group(1)
            if not shape.fullmatch(value) or (producer.trait, value) in seen:
                continue
            seen.add((producer.trait, value))
            found.append(Fact(producer.trait, value))
    return found


def bind(ability: Ability, facts: FactStore) -> dict[str, str]:
    """Choose one value per required trait: the first one discovered."""
    return {trait: facts.values(trait)[0] for trait in ability.requires if facts.has(trait)}


def resolve(catalog: AbilityCatalog, ability: Ability, bindings: dict[str, str]) -> Ability:
    """Fill an ability's `{trait}` placeholders, validating every value.

    The command stays an argv array and is never handed to a shell, so a value
    cannot introduce a second command. It could still introduce an argument or
    a path, which is what the trait pattern is for -- and why an unknown trait
    or an unmatched value fails rather than passing the placeholder through.
    """
    command: list[str] = []
    for part in ability.command:
        def substitute(match: re.Match[str]) -> str:
            trait = match.group(1)
            if trait not in ability.requires:
                raise FactRejected(f"{ability.id} substitutes an unrequired trait: {trait}")
            if trait not in bindings:
                raise FactRejected(f"{ability.id} has no value bound for {trait}")
            value = bindings[trait]
            if not _compiled(catalog.trait_pattern(trait)).fullmatch(value):
                raise FactRejected(f"value for {trait} does not match its declared shape")
            return value

        command.append(PLACEHOLDER.sub(substitute, part))
    return replace(ability, command=tuple(command))
