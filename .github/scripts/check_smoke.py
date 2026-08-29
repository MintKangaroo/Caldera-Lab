"""Assert a smoke run really executed every ability inside the container."""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXPECTED = {
    "collect-host-identity",
    "collect-system-info",
    "collect-process-list",
    "collect-workspace-files",
}


def main(path: Path) -> int:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    completed = [r for r in records if r["event"] == "ability.completed"]

    failures: list[str] = []
    succeeded = {
        r["details"]["ability_id"] for r in completed if r["details"]["status"] == "succeeded"
    }
    for missing in sorted(EXPECTED - succeeded):
        failures.append(f"{missing} did not succeed")
    for record in completed:
        details = record["details"]
        if details["isolation"] != "docker":
            failures.append(f"{details['ability_id']} ran outside the container")

    # The workspace ability is the one that silently regressed before, so it is
    # not enough that it exited zero: it must have listed the mounted file.
    workspace = [r for r in completed if r["details"]["ability_id"] == "collect-workspace-files"]
    if not any("/workspace/sample.txt" in r["details"]["stdout"] for r in workspace):
        failures.append("collect-workspace-files did not list the mounted file")

    if not any(r["event"] == "reward.scored" for r in records):
        failures.append("no reward was scored")

    for failure in failures:
        print(f"::error::{failure}")
    print(f"checked {len(completed)} executions, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
