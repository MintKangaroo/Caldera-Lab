from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Ability:
    id: str
    name: str
    tactic: str
    technique: str
    command: tuple[str, ...]
    description: str
    risk: str = "low"


class AbilityCatalog:
    def __init__(self, abilities: tuple[Ability, ...]) -> None:
        self._abilities = {ability.id: ability for ability in abilities}

    @classmethod
    def from_json(cls, path: Path) -> AbilityCatalog:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("Ability catalog must be a list")
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
            abilities.append(
                Ability(
                    id=item["id"],
                    name=item["name"],
                    tactic=item["tactic"],
                    technique=item["technique"],
                    command=tuple(command),
                    description=item["description"],
                    risk=item.get("risk", "low"),
                )
            )
        return cls(tuple(abilities))

    def get(self, ability_id: str) -> Ability:
        try:
            return self._abilities[ability_id]
        except KeyError as exc:
            raise KeyError(f"Ability is not allowlisted: {ability_id}") from exc

    def all(self) -> tuple[Ability, ...]:
        return tuple(self._abilities.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._abilities)
