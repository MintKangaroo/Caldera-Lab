from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


@dataclass(frozen=True)
class FactPattern:
    """How one ability's output yields one trait. The group is the value."""

    trait: str
    pattern: str


@dataclass(frozen=True)
class Ability:
    id: str
    name: str
    tactic: str
    technique: str
    command: tuple[str, ...]
    description: str
    risk: str = "low"
    requires_network: bool = False
    volatile_patterns: tuple[str, ...] = ()
    """Regexes matching output that changes every run without carrying new information.

    Declared per ability rather than inferred, because a global heuristic that
    blanked every number would also erase real findings such as a uid.
    """
    requires: tuple[str, ...] = ()
    """Traits that must already be known. An ability whose traits are unknown is
    never issued, which is what makes the order of a run matter at all."""
    produces: tuple[FactPattern, ...] = ()


class AbilityCatalog:
    def __init__(
        self, abilities: tuple[Ability, ...], traits: dict[str, str] | None = None
    ) -> None:
        self._abilities = {ability.id: ability for ability in abilities}
        # A trait's shape is declared once for the whole catalog, not per
        # producing ability, so every producer and every consumer of a value
        # agrees on what that value may contain.
        self._traits = dict(traits or {})
        self._depth: dict[str, int] = {}

    def depth(self, ability_id: str) -> int:
        """How many discoveries this ability stands on.

        Zero for something runnable from the start; one more than the shallowest
        chain that can supply each trait it requires. It is a property of the
        catalog, not of a run, so it is computed once at load.
        """
        return self._depth[ability_id]

    def trait_pattern(self, trait: str) -> str:
        try:
            return self._traits[trait]
        except KeyError as exc:
            raise KeyError(f"Trait is not declared: {trait}") from exc

    def traits(self) -> dict[str, str]:
        return dict(self._traits)

    @classmethod
    def from_json(cls, path: Path) -> AbilityCatalog:
        raw = json.loads(path.read_text(encoding="utf-8"))
        # A bare list is a catalog with no traits, which is every catalog that
        # existed before abilities could depend on each other.
        if isinstance(raw, dict):
            traits = raw.get("traits", {})
            raw = raw.get("abilities")
        else:
            traits = {}
        if not isinstance(raw, list):
            raise ValueError("Ability catalog must be a list of abilities")
        if not isinstance(traits, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in traits.items()
        ):
            raise ValueError("traits must map a trait name to a pattern")
        for trait, pattern in traits.items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid pattern for trait {trait}: {exc}") from exc
            # An unanchored trait pattern would accept a value with anything
            # appended, which is the whole point of declaring the shape.
            if not (pattern.startswith("^") and pattern.endswith("$")):
                raise ValueError(f"Trait pattern must be anchored: {trait}")
        abilities: list[Ability] = []
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("Ability entry must be an object")
            command = item.get("command")
            required = ("id", "name", "tactic", "technique", "description")
            if not all(isinstance(item.get(key), str) and item[key] for key in required):
                raise ValueError("Ability metadata is incomplete")
            if (
                not isinstance(command, list)
                or not command
                or not all(isinstance(x, str) for x in command)
            ):
                raise ValueError(f"Ability command must be a non-empty array: {item.get('id')}")
            patterns = item.get("volatile_patterns", [])
            if not isinstance(patterns, list) or not all(isinstance(x, str) for x in patterns):
                raise ValueError(f"volatile_patterns must be an array of strings: {item['id']}")
            for pattern in patterns:
                # Fail at load time rather than silently skipping normalisation later.
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(
                        f"Invalid volatile_patterns regex for {item['id']}: {exc}"
                    ) from exc
            requires = tuple(_string_list(item, "requires"))
            produces = _fact_patterns(item)
            for trait in (*requires, *(producer.trait for producer in produces)):
                if trait not in traits:
                    raise ValueError(f"{item['id']} uses an undeclared trait: {trait}")
            for part in command:
                for trait in PLACEHOLDER.findall(part):
                    if trait not in requires:
                        raise ValueError(
                            f"{item['id']} substitutes {trait} without requiring it"
                        )
            abilities.append(
                Ability(
                    id=item["id"],
                    name=item["name"],
                    tactic=item["tactic"],
                    technique=item["technique"],
                    command=tuple(command),
                    description=item["description"],
                    risk=item.get("risk", "low"),
                    requires_network=bool(item.get("requires_network", False)),
                    volatile_patterns=tuple(patterns),
                    requires=requires,
                    produces=produces,
                )
            )
        catalog = cls(tuple(abilities), traits)
        catalog._reject_unreachable()
        catalog._depth = catalog._measure_depth()
        return catalog

    def _measure_depth(self) -> dict[str, int]:
        """Depth per ability, refusing a dependency cycle.

        Abilities in a cycle can never run: each waits for a trait only the
        other can supply. Nothing at runtime would report that -- they would
        just silently never be offered -- so it is refused at load.
        """
        producers: dict[str, list[str]] = {}
        for ability in self._abilities.values():
            for producer in ability.produces:
                producers.setdefault(producer.trait, []).append(ability.id)

        depths: dict[str, int] = {}
        visiting: set[str] = set()

        def measure(ability_id: str) -> int:
            if ability_id in depths:
                return depths[ability_id]
            if ability_id in visiting:
                raise ValueError(f"Ability dependencies form a cycle at {ability_id}")
            visiting.add(ability_id)
            ability = self._abilities[ability_id]
            # Every required trait must be satisfied, but each may be satisfied
            # by whichever producer needs the least discovery.
            depth = 0
            if ability.requires:
                depth = 1 + max(
                    min(measure(source) for source in producers[trait])
                    for trait in ability.requires
                )
            visiting.discard(ability_id)
            depths[ability_id] = depth
            return depth

        return {ability_id: measure(ability_id) for ability_id in self._abilities}

    def _reject_unreachable(self) -> None:
        """Refuse a catalog where an ability can never become available.

        A required trait nothing produces is a catalog bug that would otherwise
        show up as an ability that silently never runs.
        """
        produced = {
            producer.trait for ability in self._abilities.values() for producer in ability.produces
        }
        for ability in self._abilities.values():
            missing = sorted(set(ability.requires) - produced)
            if missing:
                raise ValueError(f"No ability produces {', '.join(missing)} for {ability.id}")

    def get(self, ability_id: str) -> Ability:
        try:
            return self._abilities[ability_id]
        except KeyError as exc:
            raise KeyError(f"Ability is not allowlisted: {ability_id}") from exc

    def all(self) -> tuple[Ability, ...]:
        return tuple(self._abilities.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._abilities)


def _string_list(item: dict[str, object], key: str) -> list[str]:
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(f"{key} must be an array of strings: {item.get('id')}")
    return value


def _fact_patterns(item: dict[str, object]) -> tuple[FactPattern, ...]:
    raw = item.get("produces", [])
    if not isinstance(raw, list):
        raise ValueError(f"produces must be an array: {item.get('id')}")
    patterns: list[FactPattern] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError(f"produces entry must be an object: {item.get('id')}")
        trait, pattern = entry.get("trait"), entry.get("pattern")
        if not isinstance(trait, str) or not isinstance(pattern, str) or not trait or not pattern:
            raise ValueError(f"produces entry needs a trait and a pattern: {item.get('id')}")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid produces pattern for {item.get('id')}: {exc}") from exc
        # Exactly one group, because the group is the value.
        if compiled.groups != 1:
            raise ValueError(
                f"produces pattern for {item.get('id')} must have one capturing group"
            )
        patterns.append(FactPattern(trait=trait, pattern=pattern))
    return tuple(patterns)
