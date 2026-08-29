from __future__ import annotations

from dataclasses import dataclass, field

from .catalog import AbilityCatalog


@dataclass(frozen=True)
class LabPolicy:
    max_steps: int = 8
    timeout_seconds: int = 20
    allow_network: bool = False
    require_approval: bool = True
    allowed_risks: frozenset[str] = field(default_factory=lambda: frozenset({"low"}))
    approved_abilities: frozenset[str] | None = None
    """When set, only these ability IDs may run even if the catalog allows more."""

    def validate(self, catalog: AbilityCatalog, ability_id: str, step_number: int) -> None:
        if step_number >= self.max_steps:
            raise PermissionError("Maximum plan steps reached")
        ability = catalog.get(ability_id)
        if ability.risk not in self.allowed_risks:
            raise PermissionError(
                f"Ability risk '{ability.risk}' is not enabled by the lab policy: {ability_id}"
            )
        if ability.requires_network and not self.allow_network:
            raise PermissionError(f"Ability requires network but the lab denies it: {ability_id}")
        if (
            self.require_approval
            and self.approved_abilities is not None
            and ability_id not in self.approved_abilities
        ):
            raise PermissionError(f"Ability is not in the approved set: {ability_id}")
