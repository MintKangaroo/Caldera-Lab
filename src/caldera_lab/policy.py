from __future__ import annotations

from dataclasses import dataclass

from .catalog import AbilityCatalog


@dataclass(frozen=True)
class LabPolicy:
    max_steps: int = 8
    timeout_seconds: int = 20
    allow_network: bool = False
    require_approval: bool = True

    def validate(self, catalog: AbilityCatalog, ability_id: str, step_number: int) -> None:
        if step_number >= self.max_steps:
            raise PermissionError("Maximum plan steps reached")
        ability = catalog.get(ability_id)
        if ability.risk != "low":
            raise PermissionError("Only low-risk abilities are enabled in the default lab policy")
        if self.require_approval and not self.allow_network and ability_id not in catalog.ids():
            raise PermissionError("Ability requires explicit lab approval")
