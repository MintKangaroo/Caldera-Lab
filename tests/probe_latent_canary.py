"""Reproduce the latent-risk finding: what a canary buys, and what it does not.

This is not part of the CI suite. It needs the full training budget to
converge, and that convergence is what it demonstrates -- the CI suite keeps
only the robust structural facts. Run it against a recorded run's output:

    caldera-lab run --executor docker --steps 12 --log run.jsonl
    python tests/probe_latent_canary.py run.jsonl

The finding, in three lines it prints:

  fixed hidden rate      the policy discounts it across episodes; the rate is
                         never in the state and does not need to be.
  per-episode, no canary the only evidence is the risky ability's own failure,
                         which is also the commitment -- observed too late to
                         act on. The policy sits at the no-information line.
  per-episode, canary    a cheap co-failing leaf separates observing from
                         paying. The degraded bit already in the state carries
                         it, and the policy reaches the oracle. Adding
                         per-ability failure bits to chase it instead makes it
                         worse -- the finding was information timing, not state
                         capacity.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caldera_lab import bench  # noqa: E402
from caldera_lab.catalog import AbilityCatalog  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
RISKY = "collect-process-list"
CANARY = "collect-host-identity"
RATES = (0.0, 0.9)


def main(log: Path) -> int:
    catalog = AbilityCatalog.from_json(_ROOT / "catalog" / "abilities.json")
    outcomes = bench.outcomes_from_log(log)
    missing = sorted(set(catalog.ids()) - set(outcomes))
    if missing:
        raise SystemExit(f"log is missing output for: {', '.join(missing)}")

    print(f"risky = {RISKY}, canary = {CANARY}, per-episode rate in {RATES}\n")
    print(f"{'':<24}{'no-info':>10}{'oracle':>10}{'policy':>10}{'of headroom':>14}")
    for label, canary in (("per-episode, no canary", None), ("per-episode, canary", CANARY)):
        limits = bench.latent_risk_bounds(catalog, outcomes, RISKY, RATES, canary=canary)
        print(
            f"{label:<24}{limits.no_information:>10.4f}{limits.oracle:>10.4f}"
            f"{limits.measured:>10.4f}{limits.position:>13.0f}%"
        )
    print(
        "\nExpected: the no-canary policy at ~0% (at the no-information line), the "
        "canary policy near 100% (at the oracle), using the same state either way."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_latent_canary.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
