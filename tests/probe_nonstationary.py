"""Reproduce the non-stationary finding: within-episode adaptivity is robust.

This is not part of the CI suite. It needs the full training budget to
converge, and that convergence is what it demonstrates -- the CI suite keeps
only the robust structural facts (tests/test_caldera_lab.py). Run it against a
recorded run's output that covers the whole catalog:

    caldera-lab run --executor docker --steps 12 --log run.jsonl
    python tests/probe_nonstationary.py run.jsonl

Each episode draws a low or a high rate; the probability of the high one shifts
partway through, across the point where the optimal order flips (chain-first
when the chain is usually safe, the chain deferred when it is usually doomed).
The mix decides which single order a policy that must commit should pick.

The finding, in the numbers it prints:

  commit  the best single order for the before mix, graded on the after mix,
          against the best single order for the after mix. It is stale: it
          committed to the mix, and the mix moved, so it loses until re-chosen.
  RL      the tabular policy, trained on the before mix and on the after mix,
          both graded on the after mix. The two coincide -- it did not commit
          to the mix. It reorders within an episode on the risky ability's own
          failure (the canary it already carries), so its choice never depended
          on the mix, and the shift leaves it where it was. It even clears the
          best single order for the after mix, which cannot adapt at all.

So the within-episode adaptivity that made the risky root its own canary is
also what makes the policy robust to a drifting risk: it never learned the mix
to begin with.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caldera_lab import bench  # noqa: E402
from caldera_lab.catalog import AbilityCatalog  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
RISKY = "collect-process-list"
BEFORE_HIGH, AFTER_HIGH = 0.2, 0.8  # the mix crosses the order-flip point


def main(log: Path) -> int:
    catalog = AbilityCatalog.from_json(_ROOT / "catalog" / "abilities.json")
    outcomes = bench.outcomes_from_log(log)
    missing = sorted(set(catalog.ids()) - set(outcomes))
    if missing:
        raise SystemExit(f"log is missing output for: {', '.join(missing)}")

    print(f"risky = {RISKY}, high-rate probability {BEFORE_HIGH} -> {AFTER_HIGH}\n")
    shift = bench.nonstationary_risk(
        catalog, outcomes, RISKY, before_high=BEFORE_HIGH, after_high=AFTER_HIGH,
        episodes=12000, trials=400,
    )
    print(f"{'':<8}{'stale':>10}{'adapted':>10}{'re-learning':>13}")
    print(f"{'commit':<8}{shift.commit_stale:>10.4f}{shift.commit_adapted:>10.4f}"
          f"{shift.commit_relearning:>+13.4f}")
    print(f"{'RL':<8}{shift.rl_stale:>10.4f}{shift.rl_adapted:>10.4f}"
          f"{shift.rl_relearning:>+13.4f}")
    print(
        "\nExpected: commit loses ~1 when stale and must re-choose; RL loses ~0,\n"
        "and its stale return still clears the best committed order for the new mix."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_nonstationary.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
