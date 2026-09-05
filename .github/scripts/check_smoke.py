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
    "collect-account-list",
    "collect-container-context",
    "collect-network-interfaces",
    "collect-installed-packages",
    "inspect-process-status",
    "inspect-package-contents",
    "inspect-account-identity",
}

# Each gated ability and the ability whose output unlocks it.
DEPENDENCIES = {
    "inspect-process-status": "collect-process-list",
    "inspect-package-contents": "collect-installed-packages",
    "inspect-account-identity": "collect-account-list",
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

    # A gated ability that ran before the ability supplying its facts would mean
    # the precondition was not enforced -- it would have run on a stale or
    # invented value rather than a discovered one.
    order = [r["details"]["ability_id"] for r in completed]
    for gated, source in DEPENDENCIES.items():
        if gated not in order:
            failures.append(f"{gated} never ran, so its dependency was not exercised")
        elif source not in order or order.index(source) > order.index(gated):
            failures.append(f"{gated} ran before {source} supplied its facts")
    approved = [r for r in records if r["event"] == "ability.approved"]
    for record in approved:
        details = record["details"]
        if details["ability_id"] in DEPENDENCIES and not details.get("bindings"):
            failures.append(f"{details['ability_id']} was approved with no discovered value")

    # The sandbox claims to have no network. /proc/net/dev is the evidence:
    # anything beyond loopback means the isolation regressed.
    interfaces = [
        r for r in completed if r["details"]["ability_id"] == "collect-network-interfaces"
    ]
    for record in interfaces:
        names = [
            line.split(":")[0].strip()
            for line in record["details"]["stdout"].splitlines()
            if ":" in line and not line.strip().startswith(("Inter-", "face"))
        ]
        if names != ["lo"]:
            failures.append(f"sandbox exposed interfaces beyond loopback: {names}")

    for failure in failures:
        print(f"::error::{failure}")
    print(f"checked {len(completed)} executions, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
