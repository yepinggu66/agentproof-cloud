"""The neutral event model.

Everything agentproof records is expressed in one vocabulary, defined here.
Adapters translate a framework's native events into these; the recorder, the
policy layer, the chain, and the evidence pack only ever see this shape.

Keeping the vocabulary small and stable is what makes the tool
vendor-neutral. If we had modelled LangGraph's or OpenAI's event shapes
directly, every new framework would mean a new core schema.

Event kinds
-----------
``agent.start``     an agent session began
``agent.end``       an agent session finished
``llm.call``        a model was invoked
``tool.call``       a tool was invoked (this is what a policy gates)
``tool.result``     a tool returned
``error``           something failed
``note``            free-form annotation from the host application
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = ["EventKind", "AgentEvent", "EVENT_KINDS"]


class EventKind(str, Enum):
    AGENT_START = "agent.start"
    AGENT_END = "agent.end"
    LLM_CALL = "llm.call"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    ERROR = "error"
    NOTE = "note"


EVENT_KINDS = tuple(k.value for k in EventKind)


@dataclass
class AgentEvent:
    """One normalized observation.

    ``payload`` holds framework-specific detail verbatim. We do not interpret
    it — interpretation is the policy layer's job, and it operates on
    ``action``/``inputs`` extracted by the adapter.
    """

    kind: EventKind
    ts: str
    agent: str = ""
    action: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    #: Free-form marker the host can set, e.g. "regression-target" or
    #: "expected-failure". Used by the regression generator.
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "ts": self.ts,
            "agent": self.agent,
            "action": self.action,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "error": self.error,
            "payload": self.payload,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentEvent":
        return cls(
            kind=EventKind(data["kind"]),
            ts=str(data.get("ts", "")),
            agent=str(data.get("agent", "")),
            action=str(data.get("action", "")),
            inputs=dict(data.get("inputs") or {}),
            outputs=dict(data.get("outputs") or {}),
            error=data.get("error"),
            payload=dict(data.get("payload") or {}),
            tags=list(data.get("tags") or []),
        )

    @staticmethod
    def now_ts() -> str:
        return (
            _dt.datetime.now(_dt.timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
