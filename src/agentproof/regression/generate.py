"""Turn a failure trace into a replayable regression case.

The premise: when an agent fails in production, the failure is a bug you can
reproduce — if you freeze it correctly. A raw log is not a test case. A test
case needs frozen inputs, the exact tool sequence, and assertions that say
what "correct" means.

Generation rules
----------------
* Only ``tool.call`` events become steps. LLM calls are recorded as context
  but are not asserted on, because a model may legitimately phrase its
  reasoning differently while still behaving correctly.
* A case is a *failure* case when the trace contains an error event, or when
  the host tagged the trace with ``expected-failure``.
* Assertions are derived from what the trace actually did, so the generated
  case passes against the recorded behaviour. To assert the *correct*
  behaviour instead, edit ``expect`` in the YAML — the file is meant to be
  reviewed by a human before it enters CI.

Generated YAML shape::

    version: 1
    name: kb-search-timeout
    source_trace: traces/incident-2026-10-27.jsonl
    agent: support-agent
    created_from: error
    steps:
      - action: kb.search
        inputs: {query: "refund policy"}
        expect:
          decision: allow
    assertions:
      - type: action_sequence
        value: [kb.search]
      - type: no_errors
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..capture.events import AgentEvent, EventKind
from ..core.canonical import digest_bytes

__all__ = ["RegressionCase", "generate_case", "generate_cases", "load_case"]


@dataclass
class RegressionCase:
    """A replayable, human-reviewable regression case."""

    name: str
    agent: str = ""
    source_trace: str = ""
    created_from: str = "trace"
    description: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "name": self.name,
            "agent": self.agent,
            "source_trace": self.source_trace,
            "created_from": self.created_from,
            "description": self.description,
            "steps": self.steps,
            "assertions": self.assertions,
            "context": self.context,
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            self.to_dict(),
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    def save(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.to_yaml(), encoding="utf-8")
        return out

    @property
    def digest(self) -> str:
        return digest_bytes(self.to_dict())


def _slug(text: str) -> str:
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in "-_ .":
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "case"


def generate_case(
    events: list[AgentEvent],
    *,
    name: str = "",
    source_trace: str = "",
) -> RegressionCase | None:
    """Generate one regression case from a trace.

    Returns ``None`` when the trace contains no tool calls — there is nothing
    to replay, and emitting an empty case would just add noise to CI.
    """
    tool_events = [e for e in events if e.kind is EventKind.TOOL_CALL]
    if not tool_events:
        return None

    errors = [e for e in events if e.kind is EventKind.ERROR]
    expected_failure = any("expected-failure" in (e.tags or []) for e in events)

    created_from = "error" if errors else ("expected-failure" if expected_failure else "trace")

    agent = next((e.agent for e in events if e.agent), "")

    steps: list[dict[str, Any]] = []
    for event in tool_events:
        steps.append(
            {
                "action": event.action,
                "inputs": event.inputs,
                "expect": {"decision": "allow"},
            }
        )

    assertions: list[dict[str, Any]] = [
        {
            "type": "action_sequence",
            "value": [e.action for e in tool_events],
        }
    ]

    # A case generated from a failing trace is a regression test for that
    # failure: it asserts the error does NOT recur. The original error is
    # kept in `context.original_errors` for a human to read, not asserted —
    # asserting both "no errors" and "these actions errored" would be
    # self-contradictory.
    if errors:
        assertions.append({"type": "no_errors"})

    context: dict[str, Any] = {}
    if errors:
        context["original_errors"] = [
            {
                "action": e.action,
                "error": e.error,
                "ts": e.ts,
            }
            for e in errors
        ]

    case_name = name or _slug(
        errors[0].action if errors and errors[0].action else (tool_events[0].action or "case")
    )

    return RegressionCase(
        name=case_name,
        agent=agent,
        source_trace=source_trace,
        created_from=created_from,
        description=(
            f"Auto-generated from a trace with {len(tool_events)} tool call(s)"
            + (f" and {len(errors)} error(s)" if errors else "")
            + ". Review the `expect` blocks before running this in CI."
        ),
        steps=steps,
        assertions=assertions,
        context=context,
    )


def generate_cases(
    events: list[AgentEvent], *, source_trace: str = ""
) -> list[RegressionCase]:
    """Split a trace into per-agent cases, one per agent that made tool calls."""
    by_agent: dict[str, list[AgentEvent]] = {}
    for event in events:
        if event.kind is not EventKind.TOOL_CALL:
            continue
        by_agent.setdefault(event.agent or "default", []).append(event)

    cases: list[RegressionCase] = []
    for agent, agent_events in by_agent.items():
        # Rebuild the full trace for this agent plus surrounding context so
        # error events that belong to it are included.
        relevant = [e for e in events if (e.agent or "default") == agent]
        case = generate_case(relevant, source_trace=source_trace)
        if case:
            cases.append(case)
    return cases


def load_case(path: str | Path) -> RegressionCase:
    """Load a regression case from YAML."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"regression case {path} must contain a mapping")
    if "steps" not in raw:
        raise ValueError(f"regression case {path} is missing 'steps'")
    return RegressionCase(
        name=str(raw.get("name") or Path(path).stem),
        agent=str(raw.get("agent") or ""),
        source_trace=str(raw.get("source_trace") or ""),
        created_from=str(raw.get("created_from") or "trace"),
        description=str(raw.get("description") or ""),
        steps=list(raw.get("steps") or []),
        assertions=list(raw.get("assertions") or []),
        context=dict(raw.get("context") or {}),
    )
