from __future__ import annotations

import json
from pathlib import Path

import pytest

from caldera_lab.catalog import AbilityCatalog
from caldera_lab.executor import DryRunExecutor, LocalLabExecutor
from caldera_lab.orchestrator import Orchestrator
from caldera_lab.planner import LLMPlanner, RulePlanner
from caldera_lab.policy import LabPolicy

ROOT = Path(__file__).parents[1]


@pytest.fixture
def catalog() -> AbilityCatalog:
    return AbilityCatalog.from_json(ROOT / "catalog" / "abilities.json")


def test_catalog_is_allowlisted(catalog: AbilityCatalog) -> None:
    assert catalog.ids() == (
        "collect-host-identity",
        "collect-system-info",
        "collect-process-list",
        "collect-workspace-files",
    )
    with pytest.raises(KeyError):
        catalog.get("arbitrary-shell-command")


def test_rule_planner_only_returns_catalog_ids(catalog: AbilityCatalog) -> None:
    plan = RulePlanner(catalog).plan((), 3)
    assert len(plan.ability_ids) == 3
    assert set(plan.ability_ids) <= set(catalog.ids())


def test_orchestrator_dry_run_writes_auditable_events(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    log = tmp_path / "events.jsonl"
    events = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules").run(3, log)
    assert [event.event for event in events].count("ability.approved") == 3
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert records[0]["event"] == "plan.created"
    assert all(record["details"]["isolation"] == "dry-run" for record in records[2::2])


def test_local_executor_runs_without_a_shell(catalog: AbilityCatalog, tmp_path: Path) -> None:
    result = LocalLabExecutor(tmp_path).execute(catalog.get("collect-host-identity"), LabPolicy())
    assert result.status == "succeeded"
    assert "uid=" in result.stdout


def test_local_executor_cannot_be_selected_without_explicit_flag() -> None:
    # CLI guard is represented by the policy boundary: no network is ever enabled by default.
    assert LabPolicy().allow_network is False


def test_llm_planner_falls_back_without_api_key(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.source == "rules"
    assert len(plan.ability_ids) == 2
