from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .catalog import AbilityCatalog


@dataclass(frozen=True)
class Plan:
    ability_ids: tuple[str, ...]
    rationale: str
    source: str


class RulePlanner:
    def __init__(self, catalog: AbilityCatalog) -> None:
        self.catalog = catalog

    def plan(self, observations: tuple[str, ...], limit: int) -> Plan:
        ids = self.catalog.ids()[:limit]
        return Plan(ids, "Deterministic baseline sequence for the isolated lab.", "rules")


class LLMPlanner:
    """Optional OpenAI-compatible planner; every returned ID is validated locally."""

    def __init__(self, catalog: AbilityCatalog, endpoint: str | None = None) -> None:
        self.catalog = catalog
        self.endpoint = endpoint or os.getenv("CALDERA_LLM_ENDPOINT", "https://api.openai.com/v1/responses")
        self.model = os.getenv("CALDERA_LLM_MODEL", "gpt-4.1-mini")

    def plan(self, observations: tuple[str, ...], limit: int) -> Plan:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return RulePlanner(self.catalog).plan(observations, limit)
        allowed = [{"id": a.id, "description": a.description} for a in self.catalog.all()]
        prompt = {
            "task": "Choose the next low-risk ability IDs for an isolated adversary-emulation lab.",
            "allowed_abilities": allowed,
            "observations": observations[-8:],
            "max_steps": limit,
            "output": {"ability_ids": ["string"], "rationale": "string"},
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps({"model": self.model, "input": json.dumps(prompt)}).encode(),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                body = json.loads(response.read().decode())
            text = _response_text(body)
            result = json.loads(text)
            ids = tuple(
                item for item in result.get("ability_ids", []) if item in self.catalog.ids()
            )
            if ids:
                return Plan(
                    ids[:limit], str(result.get("rationale", "LLM constrained plan")), "llm"
                )
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            pass
        return RulePlanner(self.catalog).plan(observations, limit)


def _response_text(body: dict[str, Any]) -> str:
    if isinstance(body.get("output_text"), str):
        return body["output_text"]
    for item in body.get("output", []):
        for content in item.get("content", []):
            if isinstance(content.get("text"), str):
                return content["text"]
    raise ValueError("LLM response contained no text")
