from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field

from .catalog import AbilityCatalog
from .executor import Executor
from .facts import resolve
from .policy import LabPolicy


class BeaconUnauthorised(RuntimeError):
    """The server rejected the token. Retrying cannot help."""


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
    attempts: int = 3
    backoff_seconds: float = 0.2
    transport_errors: int = field(default=0, init=False)
    reregistrations: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.agent_id = self.agent_id or f"agent-{uuid.uuid4().hex[:8]}"

    def _request(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps({"agent_id": self.agent_id, **payload}).encode(),
            headers={"Content-Type": "application/json", "X-Caldera-Token": self.token},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode())
        return body if isinstance(body, dict) else {}

    def _post(
        self, path: str, payload: dict[str, object], _retrying: bool = False
    ) -> dict[str, object]:
        """Post with bounded retries, distinguishing what retrying can fix.

        A dropped connection is worth another attempt; a rejected token is not,
        and an agent the server has forgotten needs to register again rather
        than beacon into a 403 loop.
        """
        last: Exception | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                return self._request(path, payload)
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    raise BeaconUnauthorised("beacon server rejected the run token") from exc
                if exc.code == 403 and path != "/register" and not _retrying:
                    # The server restarted or forgot us; re-register once.
                    self.reregistrations += 1
                    self._post("/register", {}, _retrying=True)
                    return self._post(path, payload, _retrying=True)
                raise
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last = exc
                self.transport_errors += 1
                if attempt < self.attempts:
                    time.sleep(self.backoff_seconds * attempt)
        raise ConnectionError(f"beacon unreachable after {self.attempts} attempts: {last}")

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
            # The wire only carries an ID and values; the command comes from
            # the local catalog, and the policy still has to approve it.
            raw = instruction.get("bindings")
            bindings = {
                str(trait): str(value)
                for trait, value in (raw or {}).items()
                if isinstance(raw, dict)
            }
            ability = resolve(self.catalog, self.catalog.get(ability_id), bindings)
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
