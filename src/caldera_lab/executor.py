from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .catalog import Ability
from .policy import LabPolicy


@dataclass(frozen=True)
class ExecutionResult:
    ability_id: str
    status: str
    stdout: str
    stderr: str
    return_code: int
    isolation: str
    duration_seconds: float = 0.0


class Executor(Protocol):
    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult: ...


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
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ExecutionResult(
                ability.id, "failed", "", str(exc), -1, "local-dev", time.monotonic() - started
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
    ) -> None:
        self.image = image
        # The catalog exposes a /workspace discovery ability, so the lab must actually
        # mount one. It is bind-mounted read-only: the agent may list it, never write it.
        self.workspace = workspace or Path(".runtime/workspace").resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    def execute(self, ability: Ability, policy: LabPolicy) -> ExecutionResult:
        command = [
            "docker",
            "run",
            "--rm",
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
                timeout=policy.timeout_seconds + 10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ExecutionResult(
                ability.id, "failed", "", str(exc), -1, "docker", time.monotonic() - started
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


def result_json(result: ExecutionResult) -> str:
    return json.dumps(result.__dict__, ensure_ascii=False)
