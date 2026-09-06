"""Reproduce the planner comparison: what learning the order buys over rules.

This is not part of the CI suite. It needs the full training budget to
converge, and that convergence is what it demonstrates -- the CI suite keeps
only the robust structural facts (tests/test_caldera_lab.py). Run it against a
recorded run's output that covers the whole catalog:

    caldera-lab run --executor docker --steps 12 --log run.jsonl
    python tests/probe_planner.py run.jsonl

The lab's model-backed planners do not compete on ordering: the LLM planner
only reorders ability ids that are re-validated against the local catalog, and
the Claude planner refuses this task and falls back to rules (see the Claude
planner section of the README). So the contest is the rules planner's fixed
catalog order against a policy that learns the order.

The finding, in the numbers it prints:

  clean   the catalog order is middling -- about a fifth of the way from the
          worst feasible order to the best -- and the learned policy reaches
          the best (the DP optimum). Ordering alone is worth the full headroom.
  faults  when the risky root fails some of the time, the fixed order cannot
          respond; the learned policy defers the doomed chain and keeps the
          lead. The DP bounds do not hold under faults, so only the two
          policies are compared.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caldera_lab import bench  # noqa: E402
from caldera_lab.catalog import AbilityCatalog  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
RISKY = "collect-process-list"
FAULT_RATES = (0.3, 0.5, 0.7)


def main(log: Path) -> int:
    catalog = AbilityCatalog.from_json(_ROOT / "catalog" / "abilities.json")
    outcomes = bench.outcomes_from_log(log)
    missing = sorted(set(catalog.ids()) - set(outcomes))
    if missing:
        raise SystemExit(f"log is missing output for: {', '.join(missing)}")

    clean = bench.planner_comparison(catalog, outcomes, episodes=12000, trials=400)
    print("clean run (DP bounds hold)")
    print(f"  worst feasible order  {clean.worst:.4f}")
    print(f"  rules (catalog order) {clean.rules:.4f}   {clean.rules_position:.0f}% of headroom")
    print(f"  RL (learned order)    {clean.rl:.4f}   gain over rules {clean.rl_gain:+.4f}")
    print(f"  best feasible order   {clean.best:.4f}")
    print(f"\nunder a fault on {RISKY} (DP bounds do not hold; policies only)")
    print(f"  {'rate':>6}{'rules':>10}{'RL':>10}{'gain':>9}")
    for rate in FAULT_RATES:
        faulted = bench.planner_comparison(
            catalog, outcomes, episodes=12000, trials=400,
            fault_rates={RISKY: rate},
        )
        print(f"  {rate:>6.1f}{faulted.rules:>10.4f}{faulted.rl:>10.4f}{faulted.rl_gain:>+9.4f}")
    print(
        "\nExpected: the catalog order is middling and RL reaches the optimum on a\n"
        "clean run; under faults RL keeps a clear lead the fixed order cannot."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_planner.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
