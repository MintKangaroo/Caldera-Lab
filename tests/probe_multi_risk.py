"""Reproduce the multi-risk finding: how far one degraded bit goes with several.

This is not part of the CI suite. It needs the full training budget to
converge, and that convergence is what it demonstrates -- the CI suite keeps
only the robust structural facts (tests/test_caldera_lab.py). Run it against a
recorded run's output that covers the whole catalog:

    caldera-lab run --executor docker --steps 12 --log run.jsonl
    python tests/probe_multi_risk.py run.jsonl

One risk needed one bit: the degraded bit was 0 in the safe world and 1 in the
bad one, so it named the world exactly. This asks what happens with two
independent risks on two chains, each with a canary.

The finding, in the numbers it prints:

  correlated  the two risks share one draw, so there are still two worlds and
              one bit names them exactly -- it reaches the oracle.
  independent the risks are drawn apart, so there are four worlds. One bit
              still flips on any failure, separating all-safe from
              something-failed, but it cannot say which risk fired. It captures
              most of the ceiling -- the safe/unsafe split is the biggest lever.

`per_risk` adds a failure bit per risk (watching each canary), so the state can
name which one fired. It can, and it eventually helps -- but the four-times
larger state converges so slowly that at a practical budget one bit wins
outright, and even at a large budget `per_risk` has not reached the oracle
(the canary's own misses cap it). Naming the culprit is representable and real,
but it does not pay: the same lesson as the single risk, where a second bit
only slowed convergence.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caldera_lab import bench  # noqa: E402
from caldera_lab.catalog import AbilityCatalog  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
RISKS = ("collect-process-list", "collect-account-list")
CANARIES = ("collect-host-identity", "collect-system-info")
RATES = (0.0, 0.9)


def main(log: Path) -> int:
    catalog = AbilityCatalog.from_json(_ROOT / "catalog" / "abilities.json")
    outcomes = bench.outcomes_from_log(log)
    missing = sorted(set(catalog.ids()) - set(outcomes))
    if missing:
        raise SystemExit(f"log is missing output for: {', '.join(missing)}")

    print(f"risks = {RISKS}, canaries = {CANARIES}, per-risk rate in {RATES}\n")
    header = f"{'':<14}{'worlds':>7}{'no-info':>9}{'oracle':>9}{'one-bit':>16}{'per-risk':>16}"
    print(header)
    for label, correlated in (("correlated", True), ("independent", False)):
        limits = bench.multi_risk_bounds(
            catalog, outcomes, RISKS, canaries=CANARIES, correlated=correlated,
            episodes=12000, trials=400,
        )
        print(
            f"{label:<14}{limits.worlds:>7}{limits.no_information:>9.4f}{limits.oracle:>9.4f}"
            f"{limits.one_bit:>10.4f} {limits.position:>4.0f}%"
            f"{limits.per_risk:>10.4f} {limits.per_risk_position:>4.0f}%"
        )
    # The per-risk bits keep converging past a normal budget; show that they
    # eventually overtake one bit on the independent mix even though they start
    # far behind (the four-times larger state learns slowly).
    late = bench.multi_risk_bounds(
        catalog, outcomes, RISKS, canaries=CANARIES, correlated=False,
        episodes=25000, trials=400,
    )
    print(
        f"\nindependent at 25000 episodes: one-bit {late.position:.0f}%, "
        f"per-risk {late.per_risk_position:.0f}%"
    )
    print(
        "\nExpected: correlated near 100% (one bit names the world). Independent:\n"
        "one bit captures most of the ceiling; per-risk starts far behind and only\n"
        "overtakes it with a much larger budget, still short of the oracle -- naming\n"
        "the culprit is representable but does not pay at a practical budget."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_multi_risk.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
