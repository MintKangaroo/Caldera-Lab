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
              the bit names them exactly -- it reaches the oracle.
  independent the risks are drawn apart, so there are four worlds. The bit
              still flips on any failure, separating all-safe from
              something-failed, but it cannot say which risk fired, and the
              right order differs by which one did. It captures most of the
              ceiling -- the safe/unsafe split is the biggest lever -- but
              leaves the part that needs naming the culprit.

So one bit is enough exactly while the risks move together. Telling independent
risks apart is what the single bit cannot do; carrying which one fired would
need a bit per risk, which is the opposite of the single-risk lesson (there a
second bit only slowed convergence).
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
    print(f"{'':<12}{'worlds':>7}{'no-info':>10}{'oracle':>10}{'one-bit':>10}{'of headroom':>14}")
    for label, correlated in (("correlated", True), ("independent", False)):
        limits = bench.multi_risk_bounds(
            catalog, outcomes, RISKS, canaries=CANARIES, correlated=correlated,
            episodes=12000, trials=400,
        )
        print(
            f"{label:<12}{limits.worlds:>7}{limits.no_information:>10.4f}"
            f"{limits.oracle:>10.4f}{limits.one_bit:>10.4f}{limits.position:>13.0f}%"
        )
    print(
        "\nExpected: correlated near 100% (one bit names the world), independent\n"
        "short of it (one bit cannot say which of the two risks fired)."
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tests/probe_multi_risk.py <audit-log.jsonl>")
    raise SystemExit(main(Path(sys.argv[1])))
