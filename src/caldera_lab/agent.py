from __future__ import annotations

import json
import urllib.request
import uuid
from dataclasses import dataclass

from .catalog import AbilityCatalog
from .executor import Executor
from .policy import LabPolicy


@dataclass
class BeaconAgent:
    """A lab-side supervisor that beacons over loopback and runs abilities.

    The agent, not the container, is what talks to the beacon server. Sandboxed
    containers therefore keep `--network none`: nothing inside them ever needs
    a socket. The server sends an ability ID; this agent resolves it against
    its own catalog, so a command string can never arrive over the wire.
    """

    catalog: AbilityCatalog
    executor: Executor
    url: str
    token: str
    policy: LabPolicy
    agent_id: str = ""
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.agent_id = self.agent_id or f"agent-{uuid.uuid4().hex[:8]}"

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps({"agent_id": self.agent_id, **payload}).encode(),
            headers={"Content-Type": "application/json", "X-Caldera-Token": self.token},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode())
        return body if isinstance(body, dict) else {}

    def register(self) -> dict[str, object]:
        return self._post("/register", {})

    def run(self, max_beacons: int = 8) -> list[str]:
        """Beacon until the server has nothing left, or the budget runs out."""
        self.register()
        executed: list[str] = []
        for _ in range(max_beacons):
            instruction = self._post("/beacon", {})
            ability_id = instruction.get("ability_id")
            if not isinstance(ability_id, str):
                break
            # The wire only carries an ID; the command comes from the local
            # catalog, and the policy still has to approve it.
            ability = self.catalog.get(ability_id)
            self.policy.validate(self.catalog, ability_id, len(executed))
            result = self.executor.execute(ability, self.policy)
            self._post(
                "/result",
                {
                    "ability_id": result.ability_id,
                    "status": result.status,
                    "return_code": result.return_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "isolation": result.isolation,
                    "duration_seconds": result.duration_seconds,
                },
            )
            executed.append(ability_id)
        return executed
