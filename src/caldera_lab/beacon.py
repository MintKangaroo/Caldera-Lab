from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .catalog import AbilityCatalog

LOOPBACK = "127.0.0.1"
MAX_BODY_BYTES = 256 * 1024


class BeaconRefused(ValueError):
    """Raised for a configuration or request the lab will not serve."""


class UnknownAgent(LookupError):
    """Raised when a request names an agent that never registered."""


@dataclass
class AgentRecord:
    agent_id: str
    registered_at_beacons: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


class BeaconState:
    """Hands out ability IDs and collects results. It never emits a command.

    The server can only name an ability the agent already has in its own
    catalog, so a compromised or spoofed server cannot introduce a new command
    into the lab. This is the same boundary the LLM planner sits behind.
    """

    def __init__(self, catalog: AbilityCatalog, queue: tuple[str, ...] = ()) -> None:
        self.catalog = catalog
        for ability_id in queue:
            self.catalog.get(ability_id)
        self.queue: list[str] = list(queue)
        self.agents: dict[str, AgentRecord] = {}
        self.token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()

    def register(self, agent_id: str) -> dict[str, Any]:
        with self._lock:
            self.agents.setdefault(agent_id, AgentRecord(agent_id))
        return {"agent_id": agent_id, "abilities": list(self.catalog.ids())}

    def next_ability(self, agent_id: str) -> dict[str, Any]:
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                raise UnknownAgent(agent_id)
            record.registered_at_beacons += 1
            ability_id = self.queue.pop(0) if self.queue else None
        return {"ability_id": ability_id}

    def record_result(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        ability_id = payload.get("ability_id")
        if not isinstance(ability_id, str):
            raise BeaconRefused("result is missing ability_id")
        # A result for something the catalog does not declare is not a result
        # from this lab, whatever the agent claims. Distinguished from an
        # unregistered agent so the two do not report as the same failure.
        try:
            self.catalog.get(ability_id)
        except KeyError as exc:
            raise BeaconRefused(
                f"result names an ability outside the catalog: {ability_id}"
            ) from exc
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                raise UnknownAgent(agent_id)
            record.results.append(
                {
                    "ability_id": ability_id,
                    "status": str(payload.get("status", "unknown")),
                    "return_code": int(payload.get("return_code", -1)),
                    "stdout": str(payload.get("stdout", ""))[:MAX_BODY_BYTES],
                    "stderr": str(payload.get("stderr", ""))[:MAX_BODY_BYTES],
                }
            )
        return {"accepted": True}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "caldera-lab"
    sys_version = ""

    @property
    def state(self) -> BeaconState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        # Loopback alone is not authorisation: any local process could drive the
        # lab otherwise. The token is minted per run and never persisted.
        header = self.headers.get("X-Caldera-Token", "")
        return secrets.compare_digest(header, self.state.token)

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode())
        except (ValueError, UnicodeDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorised():
            self._send(401, {"error": "unauthorised"})
            return
        payload = self._read_json()
        if payload is None:
            self._send(400, {"error": "invalid body"})
            return
        agent_id = payload.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            self._send(400, {"error": "invalid agent_id"})
            return
        try:
            if self.path == "/register":
                self._send(200, self.state.register(agent_id))
            elif self.path == "/beacon":
                self._send(200, self.state.next_ability(agent_id))
            elif self.path == "/result":
                self._send(200, self.state.record_result(agent_id, payload))
            else:
                self._send(404, {"error": "unknown endpoint"})
        except UnknownAgent:
            self._send(403, {"error": "agent is not registered"})
        except (BeaconRefused, ValueError) as exc:
            self._send(400, {"error": str(exc)})

    def do_GET(self) -> None:  # noqa: N802
        # The protocol is push-free and write-only from the agent's side; there
        # is nothing to read without a token, not even a status page.
        self._send(405, {"error": "method not allowed"})


class BeaconServer:
    """A loopback-only coordination endpoint for lab agents."""

    def __init__(self, state: BeaconState, host: str = LOOPBACK, port: int = 0) -> None:
        if host != LOOPBACK:
            raise BeaconRefused(f"the beacon server binds {LOOPBACK} only, refused: {host}")
        self.state = state
        self._server = HTTPServer((host, port), _Handler)
        self._server.state = state  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def token(self) -> str:
        return self.state.token

    def start(self) -> BeaconServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> BeaconServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
