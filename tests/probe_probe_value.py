"""Reproduce the probe-value finding: a dedicated risk-probe is not worth a step.

This is not part of the CI suite. It needs the full training budget to
converge, and that convergence is what it demonstrates -- the CI suite keeps
only the robust structural facts (tests/test_caldera_lab.py). Run it against a
recorded run's output that covers the whole catalog:

    caldera-lab run --executor docker --steps 12 --log run.jsonl
    python tests/probe_probe_value.py run.jsonl

The question is the converse of the latent-risk canary. There, a real recon
read that fails at the latent rate is a free canary: it is run for what it
discovers anyway, and its early failure also picks the right order, so it
reaches the oracle. Here the probe is pure -- it reveals nothing and only its
failure carries information -- so running it is a genuine, decl-inable step.

The finding, in the numbers it prints:

  probe_use   the share of evaluated episodes the trained policy chose to run
              the probe. It is ~0 across budgets and across where the risk
              sits: the policy learns to decline it.
  gain        what having the probe on offer buys the policy over not having
              it at all. ~0, because the degraded bit flips on any failure, so
              the recon the lab runs regardless already carries the signal.
  worth       what a forced probe-first order beats committing blind by.
              Negative: paying a step (and the probe's own failure) to observe
              loses, since observation was already free.

So observation is not something this lab pays a step for. A dedicated canary
earns its place only when a real recon read cannot double as one -- which, in a
catalog where every read is cheap and one bit records any failure, never
happens here.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caldera_lab import bench  # noqa: E402
from caldera_lab.catalog import AbilityCatalog  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
RATES = (0.0, 0.9)
WEIGHTS = (0.5, 0.5)  # episodic risk: which world you are in is drawn each run


def main(log: Path) -> int:
    catalog = AbilityCatalog.from_json(_ROOT / "catalog" / "abilities.json")
    outcomes = bench.outcomes_from_log(log)
    missing = sorted(set(catalog.ids()) - set(outcomes))
    if missing:
        raise SystemExit(f"log is missing output for: {', '.join(missing)}")

    print(f"per-episode risk in {RATES}, weights {WEIGHTS} (a coin flip each run)\n")
    for risky in ("collect-process-list", "resolve-process-group"):
        print(f"risky = {risky} (depth {catalog.depth(risky)})")
        columns = ("budget", "policy", "no_probe", "gain", "worth", "probe_use")
        widths = (6, 9, 10, 8, 8, 11)
        cells = (f"{name:>{width}}" for name, width in zip(columns, widths, strict=True))
        print("  " + "".join(cells))
        for budget in (6, 8, 10, 12):
            value = bench.probe_value(
                catalog, outcomes, risky, RATES, weights=WEIGHTS, budget=budget,
                episodes=12000, trials=400,
            )
            print(
                f"  {budget:>6}{value.policy:>9.3f}{value.without_probe:>10.3f}"
                f"{value.probe_gain:>+8.3f}{value.probe_worth:>+8.3f}{value.probe_use:>10.2f}"
            )
        print()
    print(
        "Expected: probe_use ~0 and gain ~0 everywhere -- the policy declines a\n"
        "dedicated probe because the recon it runs anyway already reveals the risk."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_probe_value.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
