from __future__ import annotations

import contextlib
import json
import os
import random
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from .catalog import Ability
from .policy import LabPolicy

SUCCESS_STATUSES = frozenset({"succeeded", "planned"})
"""Statuses that count as a successful execution. "planned" is the dry-run result.

Anything else - "failed", "timed-out" - is a failure everywhere it is read: the
reward model, the report, and the CI smoke check."""


@dataclass(frozen=True)
class ExecutionResult:
    ability_id: str
    status: str
    stdout: str
    stderr: str
    return_code: int
    isolation: str
    duration_seconds: float = 0.0
    injected: bool = False
    """Whether this failure was injected rather than observed.

    A fixed read of a fixed container does not fail on its own, so studying how
    a policy behaves under failure means causing failures. Saying so in the
    audit log is the difference between a fault injection experiment and a
    misleading record.
    """


class Executor(Protocol):
    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult: ...


class FaultInjector:
    """Wraps an executor and fails a declared share of executions on purpose.

    This lab's sandbox is deterministic: the same fixed reads of the same
    throwaway container succeed every time. Half the policy's state space
    ("degraded") and the whole failure branch of the reward were therefore
    dead in every real run. This makes them live, and every result it spoils
    is marked `injected` so no reader mistakes it for something the container
    actually did.

    The ability still runs. Only the verdict is replaced, so the isolation
    boundary and the timing are exactly those of a real execution.
    """

    def __init__(
        self,
        executor: Executor,
        rate: float = 0.0,
        seed: int = 7,
        rates: dict[str, float] | None = None,
    ) -> None:
        for value in (rate, *(rates or {}).values()):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"fault rate must be between 0 and 1: {value}")
        self.executor = executor
        self.rate = rate
        # Per-ability rates are what make failure something a policy can act
        # on. A rate that is the same everywhere cannot be avoided by choosing
        # differently, so it is noise in the estimates and nothing to learn.
        self.rates = dict(rates or {})
        self.random = random.Random(seed)
        self.injected = 0

    def rate_for(self, ability_id: str) -> float:
        return self.rates.get(ability_id, self.rate)

    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult:
        result = self.executor.execute(ability, policy)
        rate = self.rate_for(ability.id)
        if rate <= 0.0 or self.random.random() >= rate:
            return result
        self.injected += 1
        return replace(
            result,
            status="failed",
            stdout="",
            stderr="fault injected by the lab; the container did not report this",
            return_code=1,
            injected=True,
        )


class DryRunExecutor:
    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult:
        return ExecutionResult(
            ability.id, "planned", " ".join(ability.command), "", 0, "dry-run", 0.0
        )


class LocalLabExecutor:
    """Explicit development fallback; never enabled by the default CLI."""

    def __init__(self, workspace: Path | None = None) -> None:
        self.workspace = workspace or Path(tempfile.mkdtemp(prefix="caldera-agent-"))
        self.workspace.mkdir(parents=True, exist_ok=True)

    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult:
        env = {"PATH": os.getenv("PATH", "/usr/bin:/bin"), "HOME": "/tmp"}
        started = time.monotonic()
        try:
            completed = subprocess.run(
                list(ability.command),
                cwd=self.workspace,
                env=env,
                capture_output=True,
                text=True,
                timeout=policy.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                ability.id,
                "timed-out",
                "",
                f"exceeded {policy.timeout_seconds}s lab timeout: {exc}"[:1000],
                -1,
                "local-dev",
                round(time.monotonic() - started, 3),
            )
        except OSError as exc:
            return ExecutionResult(
                ability.id,
                "failed",
                "",
                str(exc),
                -1,
                "local-dev",
                round(time.monotonic() - started, 3),
            )
        return ExecutionResult(
            ability.id,
            "succeeded" if completed.returncode == 0 else "failed",
            completed.stdout[-16_384:],
            completed.stderr[-16_384:],
            completed.returncode,
            "local-dev",
            round(time.monotonic() - started, 3),
        )


class DockerLabExecutor:
    """Runs one ability per throwaway container with no network and no privileges."""

    def __init__(
        self,
        image: str = "caldera-lab-agent:latest",
        workspace: Path | None = None,
        startup_grace_seconds: float = 10.0,
    ) -> None:
        self.image = image
        self.startup_grace_seconds = startup_grace_seconds
        # The catalog exposes a /workspace discovery ability, so the lab must actually
        # mount one. It is bind-mounted read-only: the agent may list it, never write it.
        self.workspace = workspace or Path(".runtime/workspace").resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult:
        # Naming the container is what makes a timeout enforceable. --rm only
        # runs if the client survives to do it, so killing the client on
        # timeout would otherwise leave the container running indefinitely.
        name = f"caldera-lab-{uuid.uuid4().hex[:12]}"
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            "--pull",
            "never",
            "--memory",
            "256m",
            "--cpus",
            "1.0",
            "--mount",
            f"type=bind,src={self.workspace},dst=/workspace,readonly",
            "--network",
            "none" if not policy.allow_network else "bridge",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            self.image,
            *ability.command,
        ]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                # Grace for image start-up; the container's own deadline is
                # enforced below by removing it.
                timeout=policy.timeout_seconds + self.startup_grace_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self._force_remove(name)
            return ExecutionResult(
                ability.id,
                "timed-out",
                "",
                f"exceeded {policy.timeout_seconds}s lab timeout: {exc}"[:1000],
                -1,
                "docker",
                round(time.monotonic() - started, 3),
            )
        except OSError as exc:
            self._force_remove(name)
            return ExecutionResult(
                ability.id,
                "failed",
                "",
                str(exc),
                -1,
                "docker",
                round(time.monotonic() - started, 3),
            )
        return ExecutionResult(
            ability.id,
            "succeeded" if completed.returncode == 0 else "failed",
            completed.stdout[-16_384:],
            completed.stderr[-16_384:],
            completed.returncode,
            "docker",
            round(time.monotonic() - started, 3),
        )

    @staticmethod
    def _force_remove(name: str) -> None:
        """Kill the container the abandoned client left behind."""
        # Best effort: if docker itself is gone there is nothing left to clean.
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["docker", "rm", "--force", name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )


def result_json(result: ExecutionResult) -> str:
    return json.dumps(result.__dict__, ensure_ascii=False)
