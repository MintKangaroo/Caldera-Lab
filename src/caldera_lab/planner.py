from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .catalog import AbilityCatalog


@dataclass(frozen=True)
class Plan:
    ability_ids: tuple[str, ...]
    rationale: str
    source: str
    diagnostics: dict[str, object] = field(default_factory=dict)
    """Why the plan looks the way it does, including a fallback's cause."""


class RulePlanner:
    def __init__(self, catalog: AbilityCatalog) -> None:
        self.catalog = catalog

    def plan(self, observations: tuple[str, ...], limit: int) -> Plan:
        ids = self.catalog.ids()[:limit]
        return Plan(ids, "Deterministic baseline sequence for the isolated lab.", "rules")


class PlannerError(Exception):
    """A recoverable planner failure that must still reach the audit log."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail[:500]


def _ability_schema(catalog: AbilityCatalog) -> dict[str, Any]:
    """Constrain the model to catalog IDs at the API boundary as well as locally."""
    return {
        "type": "object",
        "properties": {
            "ability_ids": {
                "type": "array",
                "items": {"type": "string", "enum": list(catalog.ids())},
            },
            "rationale": {"type": "string"},
        },
        "required": ["ability_ids", "rationale"],
        "additionalProperties": False,
    }


class LLMPlanner:
    """Optional OpenAI-compatible planner; every returned ID is validated locally."""

    def __init__(
        self,
        catalog: AbilityCatalog,
        endpoint: str | None = None,
        timeout: float = 15.0,
        attempts: int = 2,
    ) -> None:
        self.catalog = catalog
        self.endpoint = endpoint or os.getenv(
            "CALDERA_LLM_ENDPOINT", "https://api.openai.com/v1/responses"
        )
        self.model = os.getenv("CALDERA_LLM_MODEL", "gpt-4.1-mini")
        self.timeout = timeout
        self.attempts = max(1, attempts)

    def plan(self, observations: tuple[str, ...], limit: int) -> Plan:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return self._fallback(observations, limit, "no_api_key", "")

        diagnostics: dict[str, object] = {}
        last: PlannerError | None = None
        for attempt in range(1, self.attempts + 1):
            started = time.monotonic()
            try:
                plan, usage = self._request(api_key, observations, limit)
            except PlannerError as error:
                last = error
                diagnostics[f"attempt_{attempt}"] = {
                    "reason": error.reason,
                    "detail": error.detail,
                    "latency_seconds": round(time.monotonic() - started, 3),
                }
                continue
            diagnostics[f"attempt_{attempt}"] = {
                "reason": "ok",
                "latency_seconds": round(time.monotonic() - started, 3),
                "usage": usage,
            }
            return Plan(plan.ability_ids, plan.rationale, "llm", diagnostics)

        reason = last.reason if last else "unknown_error"
        detail = last.detail if last else ""
        return self._fallback(observations, limit, reason, detail, diagnostics)

    def _fallback(
        self,
        observations: tuple[str, ...],
        limit: int,
        reason: str,
        detail: str,
        diagnostics: dict[str, object] | None = None,
    ) -> Plan:
        base = RulePlanner(self.catalog).plan(observations, limit)
        return Plan(
            base.ability_ids,
            base.rationale,
            "rules",
            {
                **(diagnostics or {}),
                "fallback_reason": reason,
                "fallback_detail": detail,
                "attempts": self.attempts if reason != "no_api_key" else 0,
            },
        )

    def _request(
        self, api_key: str, observations: tuple[str, ...], limit: int
    ) -> tuple[Plan, dict[str, object]]:
        allowed = [{"id": a.id, "description": a.description} for a in self.catalog.all()]
        prompt = {
            "task": "Choose the next low-risk ability IDs for an isolated adversary-emulation lab.",
            "allowed_abilities": allowed,
            "observations": observations[-8:],
            "max_steps": limit,
        }
        payload = {
            "model": self.model,
            "input": json.dumps(prompt),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "caldera_plan",
                    "strict": True,
                    "schema": _ability_schema(self.catalog),
                }
            },
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise PlannerError(f"http_{exc.code}", exc.reason or "") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise PlannerError("transport_error", str(exc)) from exc
        except ValueError as exc:
            raise PlannerError("invalid_json_body", str(exc)) from exc

        text = _response_text(body)
        try:
            result = json.loads(text)
        except ValueError as exc:
            raise PlannerError("invalid_json_output", str(exc)) from exc
        if not isinstance(result, dict):
            raise PlannerError("output_not_an_object", type(result).__name__)

        proposed = result.get("ability_ids")
        if not isinstance(proposed, list):
            raise PlannerError("missing_ability_ids", "")
        # The schema already constrains the model; this is the boundary that
        # actually enforces it, since the endpoint is operator-configurable.
        ids = tuple(item for item in proposed if item in self.catalog.ids())
        rejected = [str(item)[:120] for item in proposed if item not in self.catalog.ids()]
        if not ids:
            raise PlannerError("no_allowlisted_ids", json.dumps(rejected, ensure_ascii=False))

        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        if rejected:
            usage = {**usage, "rejected_ability_ids": rejected}
        return (
            Plan(ids[:limit], str(result.get("rationale", "LLM constrained plan")), "llm"),
            usage,
        )


def _response_text(body: dict[str, Any]) -> str:
    if isinstance(body.get("output_text"), str):
        return body["output_text"]
    for item in body.get("output", []):
        for content in item.get("content", []):
            if isinstance(content.get("text"), str):
                return content["text"]
    raise PlannerError("no_text_in_response", "")
