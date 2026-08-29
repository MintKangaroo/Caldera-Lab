from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .catalog import AbilityCatalog
from .executor import SUCCESS_STATUSES


@dataclass
class RunSummary:
    run_id: str
    started: str = ""
    ended: str = ""
    planner_sources: Counter[str] = field(default_factory=Counter)
    fallback_reasons: Counter[str] = field(default_factory=Counter)
    rejected_ability_ids: Counter[str] = field(default_factory=Counter)
    succeeded: Counter[str] = field(default_factory=Counter)
    failed: Counter[str] = field(default_factory=Counter)
    isolations: Counter[str] = field(default_factory=Counter)
    reward_total: float = 0.0
    information_gain: float = 0.0
    duration_seconds: float = 0.0

    @property
    def executions(self) -> int:
        return sum(self.succeeded.values()) + sum(self.failed.values())

    def as_dict(self) -> dict[str, object]:
        """Serialise explicitly.

        dataclasses.asdict rebuilds a Counter from its items, turning
        Counter({"a": 1}) into Counter({("a", 1): 1}), which is both wrong and
        unserialisable.
        """
        return {
            "run_id": self.run_id,
            "started": self.started,
            "ended": self.ended,
            "executions": self.executions,
            "planner_sources": dict(self.planner_sources),
            "fallback_reasons": dict(self.fallback_reasons),
            "rejected_ability_ids": dict(self.rejected_ability_ids),
            "succeeded": dict(self.succeeded),
            "failed": dict(self.failed),
            "isolations": dict(self.isolations),
            "reward_total": round(self.reward_total, 6),
            "information_gain": round(self.information_gain, 6),
            "duration_seconds": round(self.duration_seconds, 3),
        }


def load_events(path: Path) -> list[dict[str, object]]:
    """Read a JSONL audit log, skipping lines that are not usable records."""
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and isinstance(record.get("event"), str):
            events.append(record)
    return events


def summarize(events: list[dict[str, object]]) -> dict[str, RunSummary]:
    runs: dict[str, RunSummary] = {}
    for record in events:
        run_id = str(record.get("run_id", "unknown"))
        summary = runs.setdefault(run_id, RunSummary(run_id))
        timestamp = str(record.get("timestamp", ""))
        summary.started = min(summary.started or timestamp, timestamp)
        summary.ended = max(summary.ended, timestamp)
        details = record.get("details")
        if not isinstance(details, dict):
            continue
        name = record["event"]

        if name in {"plan.created", "plan.replanned"}:
            summary.planner_sources[str(details.get("source", "unknown"))] += 1
            diagnostics = details.get("diagnostics")
            if isinstance(diagnostics, dict):
                _collect_diagnostics(summary, diagnostics)
        elif name == "ability.completed":
            ability_id = str(details.get("ability_id", "unknown"))
            status = str(details.get("status", ""))
            bucket = summary.succeeded if status in SUCCESS_STATUSES else summary.failed
            bucket[ability_id] += 1
            summary.isolations[str(details.get("isolation", "unknown"))] += 1
            summary.duration_seconds += float(details.get("duration_seconds") or 0.0)
        elif name == "reward.scored":
            summary.reward_total += float(details.get("total") or 0.0)
            summary.information_gain += float(details.get("information_gain") or 0.0)
    return runs


def _collect_diagnostics(summary: RunSummary, diagnostics: dict[str, object]) -> None:
    reason = diagnostics.get("fallback_reason")
    if isinstance(reason, str):
        summary.fallback_reasons[reason] += 1
    for key, value in diagnostics.items():
        if not key.startswith("attempt_") or not isinstance(value, dict):
            continue
        usage = value.get("usage")
        if isinstance(usage, dict):
            for rejected in usage.get("rejected_ability_ids", []) or []:
                summary.rejected_ability_ids[str(rejected)] += 1


def coverage(catalog: AbilityCatalog, runs: dict[str, RunSummary]) -> list[dict[str, object]]:
    """Map executions onto the ATT&CK techniques the catalog declares."""
    executed: Counter[str] = Counter()
    for summary in runs.values():
        executed.update(summary.succeeded)
    rows = []
    for ability in catalog.all():
        rows.append(
            {
                "technique": ability.technique,
                "tactic": ability.tactic,
                "ability_id": ability.id,
                "name": ability.name,
                "successes": executed.get(ability.id, 0),
            }
        )
    return sorted(rows, key=lambda row: (str(row["tactic"]), str(row["technique"])))


def render(catalog: AbilityCatalog, runs: dict[str, RunSummary]) -> str:
    lines: list[str] = []
    lines.append(f"runs: {len(runs)}")
    total_executions = sum(summary.executions for summary in runs.values())
    total_failures = sum(sum(summary.failed.values()) for summary in runs.values())
    lines.append(f"executions: {total_executions} ({total_failures} failed)")

    isolations: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    fallbacks: Counter[str] = Counter()
    rejected: Counter[str] = Counter()
    for summary in runs.values():
        isolations.update(summary.isolations)
        sources.update(summary.planner_sources)
        fallbacks.update(summary.fallback_reasons)
        rejected.update(summary.rejected_ability_ids)
    lines.append("isolation: " + (_counter_line(isolations) or "none"))
    lines.append("planner: " + (_counter_line(sources) or "none"))
    if fallbacks:
        lines.append("planner fallbacks: " + _counter_line(fallbacks))
    if rejected:
        # These are IDs a model proposed that the allowlist refused.
        lines.append("rejected ability ids: " + _counter_line(rejected))

    lines.append("")
    lines.append("ATT&CK coverage")
    lines.append(f"{'technique':<12}{'tactic':<12}{'successes':>10}  ability")
    for row in coverage(catalog, runs):
        mark = " " if row["successes"] else "!"
        lines.append(
            f"{row['technique']:<12}{row['tactic']:<12}{row['successes']:>10}{mark} {row['name']}"
        )
    uncovered = [row for row in coverage(catalog, runs) if not row["successes"]]
    if uncovered:
        lines.append(f"({len(uncovered)} technique(s) never executed successfully, marked !)")

    lines.append("")
    lines.append("runs")
    for summary in sorted(runs.values(), key=lambda item: item.started):
        lines.append(
            f"  {summary.run_id}  {summary.started}  "
            f"exec={summary.executions} fail={sum(summary.failed.values())} "
            f"reward={summary.reward_total:.3f} gain={summary.information_gain:.2f} "
            f"time={summary.duration_seconds:.2f}s"
        )
    return "\n".join(lines)


def _counter_line(counter: Counter[str]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counter.items()))
